/**
 * @file sfFileFormatValidator.js
 * @description [지능형 분석 + 보안 강화] 파일 형식 유효성 검사 유틸리티 클래스 파일입니다. (순수 유틸리티 계층)
 *
 * 이 클래스는 이미지 파일의 Magic Number와 헤더 정보를 직접 파싱하여
 * 파일의 실제 형식, 해상도, 구조적 무결성을 식별하고 검증하는 순수 함수들의 집합입니다.
 *
 * [핵심 기능]
 * 1. 지능형 분석 (getFormat): 파일 확장자를 기반으로 1차 검증 후, 실패 시에만 2차 전체 스캔을 수행하여 효율성을 높입니다.
 * 2. 안전한 해상도 파싱 (getDimensions): 브라우저 렌더링 엔진 없이 바이트를 직접 파싱하여 해상도를 안전하게 추출합니다.
 * 3. 구조적 무결성 검증 (verifyStructure): 파일이 정상적으로 끝나는지(예: EOI, IEND) 확인하여 파일 손상 여부를 판단합니다.
 *
 * 이 클래스의 모든 메서드는 인스턴스화할 필요 없이 정적(static)으로 호출할 수 있습니다.
 */
class sfFileFormatValidator {
  /**
   * @description 각 파일 형식의 시그니처를 검사하는 함수들을 모아놓은 객체입니다.
   *              이 구조는 새로운 형식을 추가하거나 수정하기 매우 용이합니다.
   */
  static formatCheckers = {
    png: (bytes, logger) => {
      const SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
      return sfFileFormatValidator._checkBytes(
        bytes,
        SIG,
        0,
        logger,
        "PNG 시그니처"
      )
        ? { magicNumber: SIG }
        : null;
    },
    apng: (bytes, logger) => {
      if (
        sfFileFormatValidator.formatCheckers.png(bytes, logger) &&
        sfFileFormatValidator._isAPNG(bytes, logger)
      ) {
        return {
          magicNumber: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
        };
      }
      return null;
    },
    jpeg: (bytes, logger) => {
      const SIG = [0xff, 0xd8];
      return sfFileFormatValidator._checkBytes(
        bytes,
        SIG,
        0,
        logger,
        "JPEG SOI 마커"
      )
        ? { magicNumber: Array.from(bytes.slice(0, 3)) }
        : null;
    },
    gif: (bytes, logger) => {
      const SIG = [0x47, 0x49, 0x46, 0x38]; // 'GIF8'
      return sfFileFormatValidator._checkBytes(
        bytes,
        SIG,
        0,
        logger,
        "GIF 시그니처"
      )
        ? { magicNumber: SIG }
        : null;
    },
    webp: (bytes, logger) => {
      const RIFF = [0x52, 0x49, 0x46, 0x46]; // 'RIFF'
      const WEBP = [0x57, 0x45, 0x42, 0x50]; // 'WEBP'
      if (
        sfFileFormatValidator._checkBytes(
          bytes,
          RIFF,
          0,
          logger,
          "RIFF 컨테이너"
        ) &&
        sfFileFormatValidator._checkBytes(
          bytes,
          WEBP,
          8,
          logger,
          "WebP 시그니처"
        )
      ) {
        return { magicNumber: Array.from(bytes.slice(0, 12)) };
      }
      return null;
    },
    svg: (bytes, logger) => {
      try {
        const textStart = new TextDecoder()
          .decode(bytes.slice(0, 256))
          .toLowerCase();
        if (textStart.includes("<svg")) {
          if (logger) logger.debug(`SVG 패턴('<svg') 발견됨`);
          return { magicNumber: null };
        }
      } catch (e) {
        /* 무시 */
      }
      return null;
    },
    bmp: (bytes, logger) => {
      const SIG = [0x42, 0x4d]; // 'BM'
      return sfFileFormatValidator._checkBytes(
        bytes,
        SIG,
        0,
        logger,
        "BMP 시그니처"
      )
        ? { magicNumber: SIG }
        : null;
    },
    ico: (bytes, logger) => {
      const SIG = [0x00, 0x00, 0x01, 0x00];
      return sfFileFormatValidator._checkBytes(
        bytes,
        SIG,
        0,
        logger,
        "ICO 시그니처"
      )
        ? { magicNumber: SIG }
        : null;
    },
    tiff: (bytes, logger) => {
      const LE = [0x49, 0x49, 0x2a, 0x00]; // Little Endian
      const BE = [0x4d, 0x4d, 0x00, 0x2a]; // Big Endian
      if (
        sfFileFormatValidator._checkBytes(
          bytes,
          LE,
          0,
          logger,
          "TIFF LE 시그니처"
        )
      )
        return { magicNumber: LE };
      if (
        sfFileFormatValidator._checkBytes(
          bytes,
          BE,
          0,
          logger,
          "TIFF BE 시그니처"
        )
      )
        return { magicNumber: BE };
      return null;
    },
    jpeg2000: (bytes, logger) => {
      const SIG = [
        0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20, 0x0d, 0x0a, 0x87, 0x0a,
      ];
      return sfFileFormatValidator._checkBytes(
        bytes,
        SIG,
        0,
        logger,
        "JPEG 2000 시그니처"
      )
        ? { magicNumber: SIG }
        : null;
    },
    avif: (bytes, logger) => {
      if (
        sfFileFormatValidator._checkBytes(
          bytes,
          [0x66, 0x74, 0x79, 0x70],
          4,
          logger,
          "ftyp 박스"
        )
      ) {
        // 'ftyp'
        const brand = new TextDecoder().decode(bytes.slice(8, 12));
        if (brand === "avif")
          return { magicNumber: Array.from(bytes.slice(4, 12)) };
      }
      return null;
    },
    heic: (bytes, logger) => {
      if (
        sfFileFormatValidator._checkBytes(
          bytes,
          [0x66, 0x74, 0x79, 0x70],
          4,
          logger,
          "ftyp 박스"
        )
      ) {
        // 'ftyp'
        const brand = new TextDecoder().decode(bytes.slice(8, 12));
        if (["heic", "heix", "hevc", "heim"].includes(brand))
          return { magicNumber: Array.from(bytes.slice(4, 12)) };
      }
      return null;
    },
  };

  static _getPrimaryFormatsFromExtension(extension) {
    switch (extension) {
      case "jpg":
      case "jpeg":
      case "jfif":
        return ["jpeg"];
      case "png":
        return ["apng", "png"];
      case "gif":
        return ["gif"];
      case "webp":
        return ["webp"];
      case "svg":
        return ["svg"];
      case "bmp":
        return ["bmp"];
      case "ico":
        return ["ico"];
      case "tif":
      case "tiff":
        return ["tiff"];
      case "jp2":
      case "jpx":
        return ["jpeg2000"];
      case "avif":
        return ["avif"];
      case "heic":
      case "heif":
        return ["heic"];
      default:
        return [];
    }
  }

  static getFormat(uint8Array, extension, logger) {
    logger.debug(`지능형 분석 시작: 확장자 '.${extension}' 기반`);
    const primaryFormats = this._getPrimaryFormatsFromExtension(extension);
    if (primaryFormats.length > 0) {
      logger.debug(
        `1차 검증: [${primaryFormats.join(", ")}] 형식(들)을 검사합니다.`
      );
      for (const format of primaryFormats) {
        const result = this.formatCheckers[format]?.(uint8Array, logger);
        if (result) {
          logger.success(
            `1차 검증 성공: 확장자와 실제 형식(${format.toUpperCase()})이 일치합니다.`
          );
          return { format, magicNumber: result.magicNumber };
        }
      }
      logger.error(
        `1차 검증 실패: 확장자(.${extension})와 파일 시그니처가 일치하지 않습니다. 2차 전체 스캔을 시작합니다.`
      );
    } else {
      logger.debug(
        `알 수 없는 확장자(.${extension}). 바로 2차 전체 스캔을 시작합니다.`
      );
    }

    const allFormats = Object.keys(this.formatCheckers);
    for (const format of allFormats) {
      if (primaryFormats.includes(format)) continue;
      const result = this.formatCheckers[format]?.(uint8Array, logger);
      if (result) {
        logger.error(
          `2차 스캔 성공: 파일의 실제 형식은 ${format.toUpperCase()} 입니다.`
        );
        return { format, magicNumber: result.magicNumber };
      }
    }

    logger.error(
      "2차 스캔 실패: 지원하는 파일 형식과 일치하는 시그니처를 찾지 못했습니다."
    );
    return null;
  }

  static getDimensions(format, uint8Array, logger) {
    try {
      switch (format) {
        case "png":
        case "apng":
          return this._parsePNGDimensions(uint8Array, logger);
        case "jpeg":
          return this._parseJPEGDimensions(uint8Array, logger);
        case "gif":
          return this._parseGIFDimensions(uint8Array, logger);
        case "bmp":
          return this._parseBMPDimensions(uint8Array, logger);
        case "jpeg2000":
          return this._parseJPEG2000Dimensions(uint8Array, logger);
        default:
          return null;
      }
    } catch (e) {
      if (logger)
        logger.error(`해상도 파싱 중 오류 발생 (${format}): ${e.message}`);
      return null;
    }
  }

  static verifyStructure(format, fileBytes, logger) {
    switch (format) {
      case "png":
      case "apng":
        return this._verifyPNGStructure(fileBytes, logger);
      case "jpeg":
        return this._verifyJPEGStructure(fileBytes, logger);
      default:
        return { isValid: true, reason: null };
    }
  }

  static _parsePNGDimensions(bytes, logger) {
    if (
      this._checkBytes(
        bytes,
        [0x49, 0x48, 0x44, 0x52],
        12,
        logger,
        "PNG IHDR 청크"
      )
    ) {
      const view = new DataView(
        bytes.buffer,
        bytes.byteOffset,
        bytes.byteLength
      );
      const width = view.getUint32(16, false);
      const height = view.getUint32(20, false);
      return { width, height };
    }
    return null;
  }

  static _parseJPEGDimensions(bytes, logger) {
    for (let i = 4; i < bytes.length - 8; i++) {
      if (bytes[i] === 0xff) {
        const marker = bytes[i + 1];
        if (marker === 0xc0 || marker === 0xc2) {
          const view = new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength
          );
          const height = view.getUint16(i + 5, false);
          const width = view.getUint16(i + 7, false);
          return { width, height };
        }
        const segmentLength = (bytes[i + 2] << 8) + bytes[i + 3];
        i += segmentLength + 1;
      }
    }
    return null;
  }

  static _parseGIFDimensions(bytes, logger) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const width = view.getUint16(6, true);
    const height = view.getUint16(8, true);
    return { width, height };
  }

  static _parseBMPDimensions(bytes, logger) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const width = view.getInt32(18, true);
    const height = Math.abs(view.getInt32(22, true));
    return { width, height };
  }

  static _parseJPEG2000Dimensions(bytes, logger) {
    const ihdrBoxSignature = [0x69, 0x68, 0x64, 0x72]; // 'ihdr'
    for (let i = 0; i < bytes.length - 8; i++) {
      if (
        this._checkBytes(
          bytes,
          ihdrBoxSignature,
          i,
          logger,
          "JPEG2000 'ihdr' 박스"
        )
      ) {
        const view = new DataView(
          bytes.buffer,
          bytes.byteOffset,
          bytes.byteLength
        );
        const height = view.getUint32(i + 4, false);
        const width = view.getUint32(i + 8, false);
        return { width, height };
      }
    }
    return null;
  }

  static _verifyPNGStructure(bytes, logger) {
    const IEND_CHUNK = [0x49, 0x45, 0x4e, 0x44];
    if (
      this._checkBytes(
        bytes,
        IEND_CHUNK,
        bytes.length - 8,
        logger,
        "PNG IEND 청크"
      )
    ) {
      return { isValid: true, reason: null };
    }
    return {
      isValid: false,
      reason: "PNG 파일의 종료(IEND) 청크가 손상되었거나 존재하지 않습니다.",
    };
  }

  static _verifyJPEGStructure(bytes, logger) {
    logger.trace("[JPEG 구조 검증] EOI(FF D9) 마커 존재 여부 검사 시작...");
    for (let i = 0; i < bytes.length - 1; i++) {
      if (bytes[i] === 0xff && bytes[i + 1] === 0xd9) {
        logger.trace(" -> 성공: EOI 마커를 파일 내에서 발견함.");
        return { isValid: true, reason: null, warning: null };
      }
    }
    logger.trace(" -> 실패: EOI 마커를 찾을 수 없음. (치명적)");
    return {
      isValid: false,
      reason: "JPEG 파일의 종료(EOI) 마커를 찾을 수 없습니다.",
    };
  }

  static _isAPNG(uint8Array, logger) {
    let i = 8;
    while (i < uint8Array.length) {
      if (i + 8 > uint8Array.length) break;
      const view = new DataView(uint8Array.buffer, uint8Array.byteOffset + i);
      const length = view.getUint32(0);
      const type = new TextDecoder().decode(uint8Array.slice(i + 4, i + 8));
      if (type === "acTL") {
        if (logger) logger.debug(`APNG 시그니처('acTL' 청크) 발견`);
        return true;
      }
      if (type === "IDAT") return false;
      const nextChunkPos = i + 12 + length;
      if (nextChunkPos <= i) break;
      i = nextChunkPos;
    }
    return false;
  }

  static _checkBytes(
    uint8Array,
    bytesToCheck,
    offset = 0,
    logger,
    description = "바이트 시퀀스"
  ) {
    if (uint8Array.length < offset + bytesToCheck.length) return false;
    const actualBytes = Array.from(
      uint8Array.slice(offset, offset + bytesToCheck.length)
    );
    if (logger && logger.deepDebugMode) {
      const toHex = (arr) =>
        arr.map((b) => b.toString(16).padStart(2, "0").toUpperCase()).join(" ");
      logger.trace(
        `[${description}] 검사 시작: offset=${offset}, 길이=${bytesToCheck.length}`
      );
      logger.trace(` - 기대값: ${toHex(bytesToCheck)}`);
      logger.trace(` - 실제값: ${toHex(actualBytes)}`);
      if (actualBytes.every((val, index) => val === bytesToCheck[index])) {
        logger.trace(` -> 일치. 검사 통과.`);
      } else {
        logger.trace(` -> 불일치 발견. 검사 중단.`);
      }
    }
    for (let i = 0; i < bytesToCheck.length; i++) {
      if (actualBytes[i] !== bytesToCheck[i]) return false;
    }
    return true;
  }

  static getExtension(fileName, logger) {
    return fileName.split(".").pop().toLowerCase();
  }

  static isExtensionValid(detectedFormat, extension, logger) {
    if (!detectedFormat) return false;

    if (detectedFormat === "apng" && extension === "png") return true;
    if (detectedFormat === "png" && extension === "apng") return false;

    return this._getPrimaryFormatsFromExtension(extension).includes(
      detectedFormat
    );
  }
}
