import 'dart:convert';
import 'dart:core';
import 'dart:math' as DartMath;

import 'package:crypto/crypto.dart';
import 'package:random_string/random_string.dart';
import 'package:uuid/uuid.dart';

import 'constants.dart' as DartSIP_C;
import 'grammar.dart';
import 'uri.dart';

import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:sdp_transform/sdp_transform.dart' as sdp_transform;

final JsonDecoder decoder = JsonDecoder();
final JsonEncoder encoder = JsonEncoder();
final DartMath.Random _random = DartMath.Random();

bool test100(String statusCode) {
  return statusCode.contains(RegExp(r'^100$'));
}

bool test1XX(String statusCode) {
  return statusCode.contains(RegExp(r'^1[0-9]{2}$'));
}

bool test2XX(String statusCode) {
  return statusCode.contains(RegExp(r'^2[0-9]{2}$'));
}

class Math {
  static double randomDouble() => _random.nextDouble();
  static int random() => _random.nextInt(0x7FFFFFFF);
}

int str_utf8_length(String string) => Uri.encodeComponent(string).length;

String decodeURIComponent(String str) {
  try {
    return Uri.decodeComponent(str);
  } catch (_) {
    return str;
  }
}

bool isDecimal(dynamic input) =>
    input != null &&
    (input is num && !input.isNaN ||
        (input is! num &&
            (double.tryParse(input) != null ||
                int.tryParse(input, radix: 10) != null)));

// Used by 'newTag'.
String createRandomToken(int size, {int base = 32}) {
  return randomAlphaNumeric(size).toLowerCase();
}

String newTag() => createRandomToken(10);

String newUUID() => Uuid().v4();

dynamic hostType(String host) {
  if (host == null) {
    return null;
  } else {
    dynamic res = Grammar.parse(host, 'host');
    if (res != -1) {
      return res['host_type'];
    }
  }
}

/**
* Hex-escape a SIP URI user.
* Don't hex-escape ':' (%3A), '+' (%2B), '?' (%3F"), '/' (%2F).
*
* Used by 'normalizeTarget'.
*/
String escapeUser(String user) => Uri.encodeComponent(decodeURIComponent(user))
    .replaceAll(RegExp(r'%3A', caseSensitive: false), ':')
    .replaceAll(RegExp(r'%2B', caseSensitive: false), '+')
    .replaceAll(RegExp(r'%3F', caseSensitive: false), '?')
    .replaceAll(RegExp(r'%2F', caseSensitive: false), '/');

/**
* Normalize SIP URI.
* NOTE: It does not allow a SIP URI without username.
* Accepts 'sip', 'sips' and 'tel' URIs and convert them into 'sip'.
* Detects the domain part (if given) and properly hex-escapes the user portion.
* If the user portion has only 'tel' number symbols the user portion is clean of 'tel' visual separators.
*/
URI? normalizeTarget(dynamic target, [String? domain]) {
  // If no target is given then raise an error.
  if (target == null) {
    return null;
    // If a URI instance is given then return it.
  } else if (target is URI) {
    return target;

    // If a string is given split it by '@':
    // - Last fragment is the desired domain.
    // - Otherwise append the given domain argument.
  } else if (target is String) {
    List<String> targetArray = target.split('@');
    String targetUser;
    String targetDomain;

    switch (targetArray.length) {
      case 1:
        if (domain == null) {
          return null;
        }
        targetUser = target;
        targetDomain = domain;
        break;
      case 2:
        targetUser = targetArray[0];
        targetDomain = targetArray[1];
        break;
      default:
        targetUser = targetArray.sublist(0, targetArray.length - 1).join('@');
        targetDomain = targetArray[targetArray.length - 1];
    }

    // Remove the URI scheme (if present).
    targetUser = targetUser.replaceAll(
      RegExp(r'^(sips?|tel):', caseSensitive: false),
      '',
    );

    // Remove 'tel' visual separators if the user portion just contains 'tel' number symbols.
    if (targetUser.contains(RegExp(r'^[-.()]*\+?[0-9\-.()]+$'))) {
      targetUser = targetUser.replaceAll(RegExp(r'[-.()]'), '');
    }

    // Build the complete SIP URI.
    target = '${DartSIP_C.SIP}:${escapeUser(targetUser)}@$targetDomain';

    // Finally parse the resulting URI.
    return URI.parse(target);
  } else {
    return null;
  }
}

String headerize(String str) {
  Map<String, String> exceptions = <String, String>{
    'Call-Id': 'Call-ID',
    'Cseq': 'CSeq',
    'Www-Authenticate': 'WWW-Authenticate',
  };

  List<String> names = str.toLowerCase().replaceAll('_', '-').split('-');
  String hname = '';
  int parts = names.length;
  int part;

  for (part = 0; part < parts; part++) {
    if (part != 0) {
      hname += '-';
    }
    hname +=
        String.fromCharCodes(<int>[names[part].codeUnitAt(0)]).toUpperCase() +
        names[part].substring(1);
  }
  if (exceptions[hname] != null) {
    hname = exceptions[hname]!;
  }

  return hname;
}

String sipErrorCause(dynamic statusCode) {
  String reason = DartSIP_C.Causes.SIP_FAILURE_CODE;
  DartSIP_C.SIP_ERROR_CAUSES.forEach((String key, List<int> value) {
    if (value.contains(statusCode)) {
      reason = key;
    }
  });
  return reason;
}

String calculateMD5(String string) {
  return md5.convert(utf8.encode(string)).toString();
}

List<dynamic> cloneArray(List<dynamic>? array) {
  return (array != null) ? array.sublist(0) : <dynamic>[];
}

String _filterSdpKeepPayloads(
  String? sdp,
  String media,
  Set<String> allowedPayloads, {
  bool keepAssociatedRtx = true,
  bool removeMediaIfEmpty = false,
}) {
  if (sdp == null || sdp.isEmpty) return sdp ?? '';

  final lines = sdp.split(RegExp(r'\r\n|\r|\n'));
  final out = <String>[];
  int i = 0;

  while (i < lines.length) {
    final line = lines[i];

    // Detecta início de seção "m=audio" ou "m=video"
    final mMatch = RegExp(r'^m=(\w+)\s').firstMatch(line);
    if (mMatch != null && mMatch.group(1) == media) {
      // coleta todas as linhas desta seção até o próximo "m=" ou EOF
      final section = <String>[];
      section.add(line);
      i++;
      while (i < lines.length && !lines[i].startsWith('m=')) {
        section.add(lines[i]);
        i++;
      }

      // Parse da linha m= para obter payloads na ordem original
      final parts = section[0].split(RegExp(r'\s+'));
      final originalPayloads =
          parts.length > 3
              ? parts.sublist(3).where((p) => p.trim().isNotEmpty).toList()
              : <String>[];

      // keptOrdered = interseção na ordem original
      final keptOrdered =
          originalPayloads.where((p) => allowedPayloads.contains(p)).toList();

      // Coleta linhas por payload dentro da seção e mapeia apt (fmtp apt=)
      final Map<String, List<String>> payloadLines = {};
      final Map<String, String> aptMap = {};

      for (var j = 1; j < section.length; j++) {
        final s = section[j];
        final payloadMatch = RegExp(
          r'^a=(?:rtpmap|fmtp|rtcp-fb):(\d+)\b',
        ).firstMatch(s);
        if (payloadMatch != null) {
          final pt = payloadMatch.group(1)!;
          payloadLines.putIfAbsent(pt, () => []).add(s);

          if (s.startsWith('a=fmtp:')) {
            final aptMatch = RegExp(r'\bapt=(\d+)\b').firstMatch(s);
            if (aptMatch != null) aptMap[pt] = aptMatch.group(1)!;
          }
        }
      }

      // Expande para incluir payloads associados (RTX) se pedido
      final finalKeep = Set<String>.from(keptOrdered);
      if (keepAssociatedRtx) {
        bool added;
        do {
          added = false;
          aptMap.forEach((pt, apt) {
            if (finalKeep.contains(apt) && !finalKeep.contains(pt)) {
              finalKeep.add(pt);
              added = true;
            }
          });
        } while (added);
      }

      if (finalKeep.isEmpty) {
        if (removeMediaIfEmpty) {
          // pula a seção inteira
          continue;
        } else {
          // para segurança, se nenhum payload permitido existia, mantemos a seção original
          out.addAll(section);
          continue;
        }
      }

      // Recria a linha m= mantendo apenas os payloads finais na ordem original
      final newPayloadOrder =
          originalPayloads.where((p) => finalKeep.contains(p)).toList();
      final newMLine =
          '${parts.sublist(0, 3).join(' ')} ${newPayloadOrder.join(' ')}';
      out.add(newMLine);

      // Agora adiciona as linhas da seção: mantém linhas sem payload explícito
      // e mantém apenas as linhas de payload que estão em finalKeep
      for (var j = 1; j < section.length; j++) {
        final s = section[j];
        final payloadMatch = RegExp(
          r'^a=(?:rtpmap|fmtp|rtcp-fb):(\d+)\b',
        ).firstMatch(s);
        if (payloadMatch != null) {
          final pt = payloadMatch.group(1)!;
          if (finalKeep.contains(pt)) {
            out.add(s);
          } else {
            // ignora linha relacionada a payload não mantido
          }
        } else {
          out.add(s); // mantém linhas sem id de payload
        }
      }
    } else {
      // linha fora da seção alvo: mantém
      out.add(line);
      i++;
    }
  }
  return out.join('\r\n');
}

/// Mantém apenas os payloads de áudio 0, 8, 101 e 126 (e RTX associados se existirem).
String removeUnwantedAudioCodecs(
  String? sdp, {
  bool keepAssociatedRtx = true,
  bool removeMediaIfEmpty = false,
}) {
  return _filterSdpKeepPayloads(
    sdp,
    'audio',
    <String>{'0', '8', '101', '126'},
    keepAssociatedRtx: keepAssociatedRtx,
    removeMediaIfEmpty: removeMediaIfEmpty,
  );
}

/// Mantém apenas o payload de vídeo 98 (e RTX associado se existirem).
String removeUnwantedVideoCodecs(
  String? sdp, {
  bool keepAssociatedRtx = true,
  bool removeMediaIfEmpty = false,
}) {
  return _filterSdpKeepPayloads(
    sdp,
    'video',
    <String>{'98'},
    keepAssociatedRtx: keepAssociatedRtx,
    removeMediaIfEmpty: removeMediaIfEmpty,
  );
}
