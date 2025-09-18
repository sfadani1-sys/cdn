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
/**
 * @file sfFileFormatAnalyzer.js
 * @description 파일 형식 스트리밍 분석 클래스 파일입니다. (서비스 계층)
 *
 * 이 클래스는 File 객체의 ReadableStream을 사용하여 파일을 청크(chunk) 단위로 읽어들이면서
 * 파일 형식을 분석하고 진행 상황을 보고하는 기능을 제공합니다.
 *
 * [핵심 역할]
 * 1.  파일 스트리밍을 관리하고, 분석에 필요한 첫 데이터 청크(firstChunk)와
 *     구조 검증에 필요한 전체 바이트 데이터(fullFileBytes)를 확보합니다.
 * 2.  최적화된 sfFileFormatValidator(저수준 유틸리티)의 함수들을 순차적으로 호출하여
 *     파일의 실제 형식, Magic Number, 해상도, 구조적 무결성 등의 정보를 식별 및 검증합니다.
 * 3.  이 모든 분석 정보를 담은 풍부한 '분석 결과 객체'를 생성하여 sfImageSanitizer(컨트롤러)에게 반환합니다.
 *
 * [주요 개선 사항]
 * - 'Maximum call stack size exceeded' 오류 해결: 미리 할당된 버퍼에 청크를 복사하는 방식으로 변경하여 스택 오버플로우를 방지합니다.
 * - 조기 종료(Early Exit) 로직 추가: 첫 청크 분석 실패 시, 불필요한 파일 읽기를 즉시 중단합니다.
 */
class sfFileFormatAnalyzer {
  /**
   * @description 파일 형식 분석을 스트림 방식으로 비동기적으로 수행합니다.
   * @static
   * @param {File} file - 분석할 File 객체.
   * @param {function} onProgress - 진행 상황을 UI에 보고하기 위한 콜백 함수 (progress, chunkBytes).
   * @param {sfImageSanitizerLog} logger - 로그를 기록할 로거 인스턴스.
   * @returns {Promise<object>} 분석 결과를 담은 상세 객체를 resolve하는 Promise.
   *          - isValid: boolean (최종 유효성 여부)
   *          - isExtensionValid: boolean (확장자와 실제 형식이 일치하는지 여부)
   *          - detectedFormat: string | null (식별된 실제 파일 형식)
   *          - magicNumber: Array<number> | null (식별에 사용된 Magic Number)
   *          - extension: string (파일의 확장자)
   *          - firstChunk: Uint8Array | null (Hex 뷰 하이라이트에 사용될 첫 청크 데이터)
   *          - dimensions: {width: number, height: number} | null (안전하게 파싱된 해상도 정보)
   *          - structuralVerification: {isValid: boolean, reason: string|null, warning: string|null} (구조 검증 결과)
   *          - structuralVerificationWarning: string | null (구조 검증에서 발생한 경고 메시지)
   *          - reason: string | null (최종 실패 사유)
   */
  static async analyze(file, onProgress, logger) {
    if (!file.stream) {
      const errorMsg = "브라우저가 파일 스트리밍을 지원하지 않습니다.";
      logger.error(errorMsg);
      return Promise.reject(errorMsg);
    }

    logger.debug(
      `sfFileFormatAnalyzer.analyze() 호출: ${file.name}, 크기: ${file.size} bytes`
    );

    // [수정] 스택 오버플로우 방지를 위해, 미리 전체 파일 크기만큼의 버퍼를 할당합니다.
    const finalFileBytes = new Uint8Array(file.size);
    let bytesRead = 0;
    let firstChunk = null;
    let detectedFormatInfo = null;
    let dimensions = null;

    const extension = sfFileFormatValidator.getExtension(file.name, logger);
    const stream = file.stream();
    const reader = stream.getReader();

    try {
      while (bytesRead < file.size) {
        const { done, value } = await reader.read();
        if (done) break;

        // [수정] 청크를 미리 할당된 버퍼의 올바른 위치에 복사합니다. (스택 오버플로우 해결)
        finalFileBytes.set(value, bytesRead);
        bytesRead += value.length;

        if (!firstChunk) {
          firstChunk = value;
          logger.debug("첫 번째 청크 수신, 빠른 식별 및 분석 시작...");

          // 'extension' 인자를 전달하여 지능형 분석을 수행합니다.
          detectedFormatInfo = sfFileFormatValidator.getFormat(
            firstChunk,
            extension,
            logger
          );

          // [개선] 조기 종료 로직: 첫 청크에서 형식을 식별 못하면 즉시 중단
          if (!detectedFormatInfo?.format) {
            logger.error(
              "첫 청크 분석 결과, 지원하는 형식이 아닙니다. 파일 읽기를 중단합니다."
            );
            await reader.cancel(); // 스트림을 강제로 종료하여 불필요한 다운로드를 막습니다.
            break;
          }

          dimensions = sfFileFormatValidator.getDimensions(
            detectedFormatInfo.format,
            firstChunk,
            logger
          );
        }

        if (onProgress) {
          onProgress(bytesRead / file.size, value);
        }
      }

      logger.debug(`파일 스트림 처리 완료. 총 ${bytesRead} bytes 읽음.`);

      const detectedFormat = detectedFormatInfo?.format || null;

      // 파일 형식을 식별하지 못한 경우(조기 종료된 경우), 여기서 분석을 최종 종료합니다.
      if (!detectedFormat) {
        return {
          isValid: false,
          detectedFormat: null,
          reason: "지원하지 않는 파일 형식입니다.",
          magicNumber: null,
          extension,
          firstChunk,
          dimensions: null,
          structuralVerification: { isValid: false, reason: "형식 식별 불가" },
        };
      }

      // 파일 형식이 식별된 경우에만 추가 분석을 진행합니다.
      const structuralVerification = sfFileFormatValidator.verifyStructure(
        detectedFormat,
        finalFileBytes,
        logger
      );
      const isExtensionValid = sfFileFormatValidator.isExtensionValid(
        detectedFormat,
        extension,
        logger
      );
      const finalIsValid = isExtensionValid && structuralVerification.isValid;

      let reason = null;
      if (!finalIsValid) {
        if (!isExtensionValid) {
          reason = `파일의 실제 형식(${detectedFormat.toUpperCase()})과 확장자(.${extension})가 일치하지 않습니다.`;
        } else {
          reason = structuralVerification.reason;
        }
      }

      return {
        isValid: finalIsValid,
        isExtensionValid: isExtensionValid,
        detectedFormat: detectedFormat,
        magicNumber: detectedFormatInfo?.magicNumber || null,
        extension: extension,
        firstChunk: firstChunk,
        dimensions: dimensions,
        structuralVerification: structuralVerification,
        structuralVerificationWarning: structuralVerification.warning || null,
        reason: reason,
      };
    } catch (error) {
      logger.error(`파일 스트림 분석 중 오류: ${error.message}`);
      return Promise.reject("파일을 읽는 중 오류가 발생했습니다.");
    }
  }
}
/**
 * @file sfMetaScannerJpeg.js
 * @description [완전 독립화] JPEG 파일의 모든 것을 분석하는 완전한 전문 스캐너.
 *
 * 이 클래스는 이제 마커 스캔, 내용 파싱, EXIF 태그 분석 등 JPEG와 관련된
 * 모든 분석을 책임지는 완전 독립적인 모듈입니다.
 * @dependency exif.min.js (이 기능을 사용하기 위해 HTML에 반드시 로드되어야 함)
 */
class sfMetaScannerJpeg {
  static JPEG_MARKERS = {
    0xffc0: { abbr: "SOF0", name: "Start of Frame 0: Baseline DCT" },
    0xffc1: { abbr: "SOF1", name: "Start of Frame 1: Extended sequential DCT" },
    0xffc2: { abbr: "SOF2", name: "Start of Frame 2: Progressive DCT" },
    0xffc3: { abbr: "SOF3", name: "Start of Frame 3: Lossless (sequential)" },
    0xffc4: { abbr: "DHT", name: "Define Huffman Table(s)" },
    0xffc5: {
      abbr: "SOF5",
      name: "Start of Frame 5: Differential sequential DCT",
    },
    0xffc6: {
      abbr: "SOF6",
      name: "Start of Frame 6: Differential progressive DCT",
    },
    0xffc7: { abbr: "SOF7", name: "Start of Frame 7: Differential lossless" },
    0xffc8: { abbr: "JPG", name: "Reserved for JPEG extensions" },
    0xffc9: {
      abbr: "SOF9",
      name: "Start of Frame 9: Extended sequential DCT, arithmetic coding",
    },
    0xffca: {
      abbr: "SOF10",
      name: "Start of Frame 10: Progressive DCT, arithmetic coding",
    },
    0xffcb: {
      abbr: "SOF11",
      name: "Start of Frame 11: Lossless (sequential), arithmetic coding",
    },
    0xffcc: { abbr: "DAC", name: "Define Arithmetic Coding Conditioning(s)" },
    0xffcd: {
      abbr: "SOF13",
      name: "Start of Frame 13: Differential sequential DCT, arithmetic coding",
    },
    0xffce: {
      abbr: "SOF14",
      name: "Start of Frame 14: Differential progressive DCT, arithmetic coding",
    },
    0xffcf: {
      abbr: "SOF15",
      name: "Start of Frame 15: Differential lossless, arithmetic coding",
    },
    0xffd0: { abbr: "RST0", name: "Restart with modulo 8 count 0" },
    0xffd1: { abbr: "RST1", name: "Restart with modulo 8 count 1" },
    0xffd2: { abbr: "RST2", name: "Restart with modulo 8 count 2" },
    0xffd3: { abbr: "RST3", name: "Restart with modulo 8 count 3" },
    0xffd4: { abbr: "RST4", name: "Restart with modulo 8 count 4" },
    0xffd5: { abbr: "RST5", name: "Restart with modulo 8 count 5" },
    0xffd6: { abbr: "RST6", name: "Restart with modulo 8 count 6" },
    0xffd7: { abbr: "RST7", name: "Restart with modulo 8 count 7" },
    0xffd8: { abbr: "SOI", name: "Start of Image" },
    0xffd9: { abbr: "EOI", name: "End of Image" },
    0xffda: { abbr: "SOS", name: "Start of Scan" },
    0xffdb: { abbr: "DQT", name: "Define Quantization Table(s)" },
    0xffdc: { abbr: "DNL", name: "Define Number of Lines" },
    0xffdd: { abbr: "DRI", name: "Define Restart Interval" },
    0xffde: { abbr: "DHP", name: "Define Hierarchical Progression" },
    0xffdf: { abbr: "EXP", name: "Expand Reference Component(s)" },
    0xffe0: { abbr: "APP0", name: "Application Segment 0 (JFIF, JFXX)" },
    0xffe1: { abbr: "APP1", name: "Application Segment 1 (EXIF, XMP)" },
    0xffe2: {
      abbr: "APP2",
      name: "Application Segment 2 (ICC Profile, FlashPix)",
    },
    0xffe3: { abbr: "APP3", name: "Application Segment 3" },
    0xffe4: { abbr: "APP4", name: "Application Segment 4" },
    0xffe5: { abbr: "APP5", name: "Application Segment 5" },
    0xffe6: { abbr: "APP6", name: "Application Segment 6" },
    0xffe7: { abbr: "APP7", name: "Application Segment 7" },
    0xffe8: { abbr: "APP8", name: "Application Segment 8" },
    0xffe9: { abbr: "APP9", name: "Application Segment 9" },
    0xffea: { abbr: "APP10", name: "Application Segment 10" },
    0xffeb: { abbr: "APP11", name: "Application Segment 11" },
    0xffec: { abbr: "APP12", name: "Application Segment 12 (Picture Info)" },
    0xffed: { abbr: "APP13", name: "Application Segment 13 (Photoshop IRB)" },
    0xffee: { abbr: "APP14", name: "Application Segment 14 (Adobe)" },
    0xffef: { abbr: "APP15", name: "Application Segment 15" },
    0xfff0: { abbr: "JPG0", name: "Reserved for JPEG extensions" },
    0xfffd: { abbr: "JPG13", name: "Reserved for JPEG extensions" },
    0xfffe: { abbr: "COM", name: "Comment" },
    0xff01: { abbr: "TEM", name: "Temporary private use in arithmetic coding" },
  };

  static STANDALONE_MARKERS = new Set([
    0xffd8, 0xffd9, 0xff01, 0xffd0, 0xffd1, 0xffd2, 0xffd3, 0xffd4, 0xffd5,
    0xffd6, 0xffd7,
  ]);
  static CRITICAL_MARKERS = new Set(["SOI", "SOF0", "SOS", "EOI"]);
  static COMMON_MARKERS = new Set(["DQT", "DHT", "APP0"]);

  static async scan(file, logger) {
    const bytes = await this._readFileAsBytes(file);
    if (!bytes) {
      return {
        errors: ["파일을 읽는 중 오류 발생"],
        metadata: [],
        skipped: false,
      };
    }
    const view = new DataView(bytes.buffer);

    const markerResult = this._scanAllMarkers(bytes, view, logger);
    const exifResult = await this._analyzeJPEG_EXIF(bytes.buffer, logger);

    if (exifResult.metadata.length > 0) {
      const app1Item = markerResult.metadata.find(
        (item) => item.key === "APP1"
      );
      if (app1Item) {
        const exifDetails = exifResult.metadata
          .map((meta) => `    - ${meta.key}: ${meta.value}`)
          .join("\n");
        app1Item.details =
          (app1Item.details ? app1Item.details + "\n" : "") + exifDetails;
      }
    }

    return {
      errors: [...markerResult.errors, ...(exifResult.errors || [])],
      warnings: [...markerResult.warnings, ...(exifResult.warnings || [])],
      metadata: markerResult.metadata,
      skipped: false,
    };
  }

  static _readFileAsBytes(file) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => resolve(new Uint8Array(e.target.result));
      reader.onerror = () => resolve(null);
      reader.readAsArrayBuffer(file);
    });
  }

  static _scanAllMarkers(bytes, view, logger) {
    if (logger) logger.trace("[JPEG 멀티-패스 스캔] 시작...");
    let allMetadata = [];
    const allFoundKeys = new Set();
    const errors = [];

    if (logger) logger.trace(" -> 1차 스캔 (메인 이미지) 시작...");
    const mainImageScan = this._scanSegment(bytes, view, 0, logger);
    allMetadata.push(...mainImageScan.metadata);
    mainImageScan.foundKeys.forEach((key) => allFoundKeys.add(key));

    let firstEoiIndex = -1;
    for (let i = mainImageScan.endOfScanIndex || 0; i < bytes.length - 1; i++) {
      if (bytes[i] === 0xff && bytes[i + 1] === 0xd9) {
        firstEoiIndex = i;
        break;
      }
    }

    if (firstEoiIndex !== -1) {
      allMetadata.push({
        key: "EOI",
        value: "End of Image",
        offset: firstEoiIndex,
        markerHex: "0xFFD9",
        length: 2,
      });
      allFoundKeys.add("EOI");
      const trailingDataIndex = firstEoiIndex + 2;
      if (trailingDataIndex < bytes.length) {
        if (logger)
          logger.trace(
            ` -> EOI 이후 후행 데이터 발견. 2차 스캔 시작 at offset=${trailingDataIndex}...`
          );
        allMetadata.push({
          key: "TRAILING_DATA",
          value: "--- 후행 데이터 시작 ---",
          offset: trailingDataIndex,
        });
        if (view.getUint16(trailingDataIndex, false) === 0xffed) {
          allMetadata.push({
            key: "INFO",
            value:
              "후행 데이터는 Photoshop 메타데이터(IRB)일 가능성이 높습니다.",
          });
        }
        const trailingScan = this._scanSegment(
          bytes,
          view,
          trailingDataIndex,
          logger
        );
        allMetadata.push(...trailingScan.metadata);
        trailingScan.foundKeys.forEach((key) => allFoundKeys.add(key));
      }
    }

    const allEssential = [...this.CRITICAL_MARKERS, ...this.COMMON_MARKERS];
    allEssential.forEach((key) => {
      if (!allFoundKeys.has(key)) {
        let markerInfo,
          markerCodeHex = "N/A";
        for (const code in this.JPEG_MARKERS) {
          if (this.JPEG_MARKERS[code].abbr === key) {
            markerInfo = this.JPEG_MARKERS[code];
            markerCodeHex = `0x${parseInt(code).toString(16).toUpperCase()}`;
            break;
          }
        }
        allMetadata.push({
          key,
          value: markerInfo.name,
          markerHex: markerCodeHex,
          isMissing: true,
        });
      }
    });

    allMetadata.sort((a, b) =>
      a.isMissing
        ? 1
        : b.isMissing
        ? -1
        : (a.offset || Infinity) - (b.offset || Infinity)
    );

    return { errors, metadata: allMetadata, warnings: [] };
  }

  static _scanSegment(bytes, view, startIndex, logger) {
    let i = startIndex;
    const metadata = [];
    const foundKeys = new Set();
    while (i < bytes.length - 1) {
      if (bytes[i] !== 0xff) {
        i++;
        continue;
      }
      const markerSecondByte = bytes[i + 1];
      if (markerSecondByte === 0x00 || markerSecondByte === 0xff) {
        i++;
        continue;
      }
      const markerCode = view.getUint16(i, false);
      const markerInfo = this.JPEG_MARKERS[markerCode];
      const markerHex = `0x${markerCode.toString(16).toUpperCase()}`;
      let newMetaItem = null;
      if (markerInfo) {
        newMetaItem = {
          key: markerInfo.abbr,
          value: markerInfo.name,
          offset: i,
          markerHex,
        };
        foundKeys.add(markerInfo.abbr);
      } else if (markerCode >= 0xff02 && markerCode <= 0xffbf) {
        newMetaItem = {
          key: `RES(${markerHex})`,
          value: "Reserved Marker",
          offset: i,
          markerHex,
        };
      }
      if (newMetaItem) {
        if (this.STANDALONE_MARKERS.has(markerCode)) {
          newMetaItem.length = 2;
          i += 2;
        } else {
          if (i + 4 > bytes.length) {
            metadata.push(newMetaItem);
            break;
          }
          const segmentLength = view.getUint16(i + 2, false);
          newMetaItem.length = segmentLength + 2;
          const dataOffset = i + 4;
          const dataLength = segmentLength - 2;
          if (dataOffset + dataLength <= bytes.length) {
            const dataSegment = bytes.slice(
              dataOffset,
              dataOffset + dataLength
            );
            newMetaItem.rawData = dataSegment;
            newMetaItem.details = null;
            switch (markerCode) {
              case 0xffe0:
                newMetaItem.details = this._parseAPP0(dataSegment);
                break;
              case 0xffe1:
                newMetaItem.details = this._parseAPP1(dataSegment);
                break;
              case 0xffdb:
                newMetaItem.details = this._parseDQT(dataSegment);
                break;
              case 0xffc0:
                newMetaItem.details = this._parseSOF0(dataSegment);
                break;
              case 0xffc4:
                newMetaItem.details = this._parseDHT(dataSegment);
                break;
              case 0xffda:
                newMetaItem.details = this._parseSOS(dataSegment);
                break;
              case 0xfffe:
                newMetaItem.details = this._parseCOM(dataSegment);
                break;
            }
          }
          if (markerCode === 0xffda) {
            metadata.push(newMetaItem);
            return {
              metadata,
              foundKeys,
              endOfScanIndex: i + segmentLength + 2,
            };
          }
          i += segmentLength + 2;
        }
        metadata.push(newMetaItem);
      } else {
        i += 2;
      }
    }
    return { metadata, foundKeys, endOfScanIndex: i };
  }

  static _parseAPP0(segmentBytes) {
    const identifier = new TextDecoder().decode(segmentBytes.slice(0, 5));
    if (identifier === "JFIF\0") {
      const major = segmentBytes[5],
        minor = segmentBytes[6],
        units = segmentBytes[7];
      const xDensity = (segmentBytes[8] << 8) | segmentBytes[9],
        yDensity = (segmentBytes[10] << 8) | segmentBytes[11];
      return `식별자: JFIF\n    버전: ${major}.${String(minor).padStart(
        2,
        "0"
      )}\n    밀도 단위: ${
        units === 0 ? "종횡비" : units === 1 ? "인치당 픽셀" : "cm당 픽셀"
      }\n    밀도: ${xDensity}x${yDensity}`;
    }
    return "Non-JFIF APP0 segment";
  }

  static _parseAPP1(segmentBytes) {
    if (segmentBytes.length < 6) return "Invalid APP1 segment";
    const identifier = new TextDecoder().decode(segmentBytes.slice(0, 6));
    if (identifier === "Exif\0\0") {
      const tiffHeaderOffset = 6;
      if (segmentBytes.length < tiffHeaderOffset + 8)
        return "Incomplete EXIF data (missing TIFF header)";
      const view = new DataView(segmentBytes.buffer, segmentBytes.byteOffset);
      const byteOrderMarker = view.getUint16(tiffHeaderOffset, false);
      const isLittleEndian = byteOrderMarker === 0x4949,
        isBigEndian = byteOrderMarker === 0x4d4d;
      let report = `식별자: Exif (${this._bytesToHexString(
        segmentBytes.slice(0, 6)
      )})\n`;
      if (isLittleEndian || isBigEndian) {
        report += `    TIFF 헤더: ${this._bytesToHexString(
          segmentBytes.slice(tiffHeaderOffset, tiffHeaderOffset + 4)
        )} (${isLittleEndian ? "Little Endian" : "Big Endian"})`;
      } else {
        report += `    TIFF 헤더: 알 수 없음`;
      }
      return report;
    }
    if (
      new TextDecoder().decode(segmentBytes.slice(0, 29)) ===
      "http://ns.adobe.com/xap/1.0/\0"
    ) {
      return `식별자: XMP (Adobe Extensible Metadata Platform)`;
    }
    return "알 수 없는 APP1 데이터";
  }

  static _parseSOF0(segmentBytes) {
    if (segmentBytes.length < 6) return "Invalid SOF0 segment";
    const view = new DataView(
      segmentBytes.buffer,
      segmentBytes.byteOffset,
      segmentBytes.byteLength
    );
    const precision = view.getUint8(0),
      height = view.getUint16(1, false),
      width = view.getUint16(3, false),
      components = view.getUint8(5);
    return `정밀도: ${precision}-bit\n    이미지 크기: ${width}x${height}\n    구성요소 수: ${components}`;
  }

  static _parseDQT(segmentBytes) {
    const precision = segmentBytes[0] >> 4 === 0 ? "8-bit" : "16-bit",
      tableId = segmentBytes[0] & 0x0f;
    return `정밀도: ${precision}, 테이블 ID: ${tableId}`;
  }

  static _parseDHT(segmentBytes) {
    const classAndId = segmentBytes[0],
      tableClass = classAndId >> 4 === 0 ? "DC" : "AC",
      tableId = classAndId & 0x0f;
    return `클래스: ${tableClass}, 테이블 ID: ${tableId}`;
  }

  static _parseSOS(segmentBytes) {
    return `구성요소 수: ${segmentBytes[0]}`;
  }

  static _parseCOM(segmentBytes) {
    try {
      const comment = new TextDecoder().decode(segmentBytes);
      return comment.length > 70 ? comment.substring(0, 70) + "..." : comment;
    } catch (e) {
      return "Invalid comment encoding";
    }
  }

  static _bytesToHexString(bytes) {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0").toUpperCase())
      .join(" ");
  }

  static _analyzeJPEG_EXIF(arrayBuffer, logger) {
    return new Promise(async (resolve) => {
      const exifData = await this.extractExifData(arrayBuffer);
      resolve(this.analyzeExifData(exifData));
    });
  }

  static extractExifData(arrayBuffer) {
    return new Promise((resolve) => {
      let resolved = false;
      const timeoutId = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          resolve({});
        }
      }, 2000);
      try {
        window.EXIF.getData(arrayBuffer, function () {
          if (!resolved) {
            clearTimeout(timeoutId);
            resolved = true;
            resolve(this.exifdata || {});
          }
        });
      } catch (error) {
        if (!resolved) {
          clearTimeout(timeoutId);
          resolved = true;
          resolve({});
        }
      }
    });
  }

  static analyzeExifData(exifData) {
    const result = { warnings: [], metadata: [] };
    if (exifData.GPSLatitude && exifData.GPSLongitude) {
      result.warnings.push("개인정보 주의: GPS 위치 정보가 포함되어 있습니다.");
      result.metadata.push({
        key: "GPS Latitude",
        value: exifData.GPSLatitude.join(", "),
      });
      result.metadata.push({
        key: "GPS Longitude",
        value: exifData.GPSLongitude.join(", "),
      });
    }
    if (exifData.UserComment) {
      result.metadata.push({
        key: "UserComment",
        value: String(exifData.UserComment),
      });
      if (this.isSuspiciousComment(String(exifData.UserComment))) {
        result.warnings.push(
          "보안 주의: UserComment에 의심스러운 내용(스크립트 등)이 포함될 수 있습니다."
        );
      }
    }
    if (exifData.Software) {
      result.metadata.push({ key: "Software", value: exifData.Software });
    }
    return result;
  }

  static isSuspiciousComment(comment) {
    return ["<script>", "eval(", "javascript:"].some((k) =>
      comment.toLowerCase().includes(k)
    );
  }
}
/**
 * @file sfMetaScannerPng.js
 * @description PNG 파일의 모든 청크(Chunk)를 스캔하고 식별하는 전문 스캐너 클래스입니다.
 *
 * 이 클래스는 PNG 파일의 바이너리 데이터를 직접 분석하여 파일의 전체 구조를
 * 청크 단위로 해부하는 저수준 분석 기능을 제공합니다.
 */
class sfMetaScannerPng {
  /**
   * @description 주요 PNG 청크 타입 정보입니다.
   */
  static PNG_CHUNK_TYPES = {
    IHDR: "Image Header (필수, 이미지 기본 정보)",
    PLTE: "Palette (색상 팔레트 정보)",
    IDAT: "Image Data (실제 이미지 데이터)",
    IEND: "Image Trailer (파일의 끝, 필수)",
    acTL: "Animation Control (APNG 애니메이션 제어)",
    fcTL: "Frame Control (APNG 프레임 제어)",
    fdAT: "Frame Data (APNG 프레임 데이터)",
    tEXt: "Textual Data (ISO/IEC 8859-1 텍스트 메타데이터)",
    zTXt: "Compressed Textual Data (압축된 텍스트 메타데이터)",
    iTXt: "International Textual Data (UTF-8 텍스트 메타데이터)",
    gAMA: "Gamma Correction (감마 값)",
    cHRM: "Primary Chromaticities (색도 값)",
    sRGB: "Standard RGB Color Space (sRGB 색 공간 정보)",
    pHYs: "Physical Pixel Dimensions (물리적 픽셀 크기)",
    tIME: "Last-modification Time (최종 수정 시간)",
  };

  /**
   * @description PNG 파일을 스캔하여 발견된 모든 청크의 목록을 반환합니다.
   * @static
   * @param {File} file - 분석할 File 객체.
   * @param {sfImageSanitizerLog} [logger] - 로그를 기록할 로거 인스턴스.
   * @returns {Promise<object>} 스캔 결과({ errors, metadata, skipped })를 담은 Promise.
   */
  static scan(file, logger) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        if (logger) logger.trace("[PNG 청크 스캔] 시작...");
        const bytes = new Uint8Array(e.target.result);
        const metadata = [];
        const errors = [];
        let i = 8; // PNG 시그니처(8바이트)를 건너뜁니다.

        while (i < bytes.length) {
          if (i + 8 > bytes.length) {
            errors.push("파일 끝에서 손상된 청크 헤더가 발견되었습니다.");
            break;
          }
          const view = new DataView(bytes.buffer, bytes.byteOffset + i);
          const length = view.getUint32(0); // 청크 데이터의 길이 (Big Endian)
          const type = new TextDecoder().decode(bytes.slice(i + 4, i + 8));

          const description = this.PNG_CHUNK_TYPES[type] || "알 수 없는 청크";
          if (logger)
            logger.trace(
              `[PNG 청크 스캔] '${type}' 청크 발견 at offset=${i}, 데이터 길이: ${length} bytes`
            );
          metadata.push({ key: type, value: description });

          // 기존의 텍스트 메타데이터 추출 로직을 여기에 통합합니다.
          if (["tEXt", "iTXt"].includes(type)) {
            const chunkData = bytes.slice(i + 8, i + 8 + length);
            const nullSeparatorIndex = chunkData.indexOf(0);
            if (nullSeparatorIndex > 0) {
              const keyword = new TextDecoder().decode(
                chunkData.slice(0, nullSeparatorIndex)
              );
              const text = new TextDecoder().decode(
                chunkData.slice(nullSeparatorIndex + 1)
              );
              // 상세 정보를 기존 로그에 추가합니다.
              const lastMeta = metadata[metadata.length - 1];
              lastMeta.value += ` - ${keyword}: ${text.substring(0, 50)}...`;
            }
          }

          if (type === "IEND") {
            if (logger)
              logger.trace(
                "[PNG 청크 스캔] IEND 청크 발견, 스캔을 종료합니다."
              );
            break; // 파일의 끝
          }

          const nextChunkPos = i + 12 + length; // 4(length)+4(type)+data(length)+4(CRC)
          if (nextChunkPos <= i || nextChunkPos > bytes.length) {
            errors.push(
              `'${type}' 청크의 길이가 비정상적이어서 스캔을 중단합니다.`
            );
            break;
          }
          i = nextChunkPos;
        }

        if (logger) logger.trace("[PNG 청크 스캔] 완료.");
        resolve({ errors, metadata, skipped: false });
      };
      reader.onerror = () =>
        resolve({
          errors: ["파일 읽기 중 오류"],
          metadata: [],
          skipped: false,
        });
      reader.readAsArrayBuffer(file);
    });
  }
}
/**
 * @file sfMetaScannerGif.js
 * @description GIF 파일의 모든 블록(Block)을 스캔하고 식별하는 전문 스캐너 클래스입니다.
 *
 * 이 클래스는 GIF 파일의 바이너리 데이터를 직접 분석하여 파일의 전체 구조를
 * 블록 단위로 해부하는 저수준 분석 기능을 제공합니다.
 */
class sfMetaScannerGif {
  /**
   * @description GIF 블록 및 확장 타입 정보입니다.
   */
  static GIF_BLOCK_TYPES = {
    HEADER: "Header (GIF87a or GIF89a)",
    LSD: "Logical Screen Descriptor (전체 이미지 정보)",
    GCT: "Global Color Table (전역 색상표)",
    0x21: {
      // Extension Introducer
      0xf9: "Graphic Control Extension (애니메이션 제어)",
      0xfe: "Comment Extension (주석)",
      0x01: "Plain Text Extension (일반 텍스트)",
      0xff: "Application Extension (애플리케이션 정보, 예: 반복)",
    },
    0x2c: "Image Descriptor (개별 프레임 정보)",
    LCT: "Local Color Table (지역 색상표)",
    DATA: "Image Data (이미지 데이터 블록)",
    0x3b: "Trailer (파일의 끝)",
  };

  /**
   * @description GIF 파일을 스캔하여 발견된 모든 블록의 목록을 반환합니다.
   * @static
   */
  static scan(file, logger) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        if (logger) logger.trace("[GIF 블록 스캔] 시작...");
        const bytes = new Uint8Array(e.target.result);
        const metadata = [];
        const errors = [];
        let i = 0;

        // 1. 헤더 (6바이트)
        const header = new TextDecoder().decode(bytes.slice(i, i + 6));
        if (header.startsWith("GIF")) {
          metadata.push({
            key: "HEADER",
            value: `${header} - ${this.GIF_BLOCK_TYPES["HEADER"]}`,
          });
          i += 6;
        } else {
          errors.push("유효한 GIF 파일 헤더가 아닙니다.");
          resolve({ errors, metadata, skipped: false });
          return;
        }

        // 2. 논리 화면 기술자 (7바이트)
        if (i + 7 <= bytes.length) {
          metadata.push({ key: "LSD", value: this.GIF_BLOCK_TYPES["LSD"] });
          const packedField = bytes[i + 4];
          const hasGCT = (packedField & 0x80) !== 0; // 최상위 비트가 1이면 GCT 존재
          i += 7;

          // 3. 전역 색상 테이블 (선택 사항)
          if (hasGCT) {
            const gctSize = 3 * 2 ** ((packedField & 0x07) + 1);
            metadata.push({
              key: "GCT",
              value: `${this.GIF_BLOCK_TYPES["GCT"]} (${gctSize} bytes)`,
            });
            i += gctSize;
          }
        }

        // 4. 데이터 블록 루프
        while (i < bytes.length) {
          const introducer = bytes[i];
          switch (introducer) {
            case 0x21: // 확장 블록
              const label = bytes[i + 1];
              const extInfo = this.GIF_BLOCK_TYPES[0x21][label];
              const key = extInfo
                ? `Ext(0x${label.toString(16).toUpperCase()})`
                : `Ext(Unknown)`;
              const value = extInfo || "알 수 없는 확장 블록";
              metadata.push({ key, value });
              if (logger)
                logger.trace(`[GIF 블록 스캔] '${value}' 발견 at offset=${i}`);

              // 기존 주석 추출 로직 통합
              if (label === 0xfe) {
                let commentData = this._extractSubBlockData(bytes, i + 2);
                metadata[
                  metadata.length - 1
                ].value += ` - ${new TextDecoder().decode(commentData)}`;
              }

              i = this._skipSubBlocks(bytes, i + 2);
              break;

            case 0x2c: // 이미지 기술자
              metadata.push({
                key: "IMG DESC",
                value: this.GIF_BLOCK_TYPES[0x2c],
              });
              if (logger)
                logger.trace(
                  `[GIF 블록 스캔] '${this.GIF_BLOCK_TYPES[0x2c]}' 발견 at offset=${i}`
                );
              // 이미지 기술자(9바이트) 건너뛰기
              i += 9;
              // TODO: Local Color Table 존재 여부 확인 및 건너뛰기
              // LZW 최소 코드 크기(1바이트) 건너뛰기
              i++;
              // 이미지 데이터 건너뛰기
              i = this._skipSubBlocks(bytes, i);
              break;

            case 0x3b: // 트레일러
              metadata.push({
                key: "TRAILER",
                value: this.GIF_BLOCK_TYPES[0x3b],
              });
              if (logger)
                logger.trace(
                  `[GIF 블록 스캔] '${this.GIF_BLOCK_TYPES[0x3b]}' 발견, 스캔을 종료합니다.`
                );
              i = bytes.length; // 루프 종료
              break;

            default:
              errors.push(
                `알 수 없는 블록 식별자(0x${introducer.toString(
                  16
                )}) at offset=${i}. 스캔을 중단합니다.`
              );
              i = bytes.length; // 루프 종료
              break;
          }
        }
        if (logger) logger.trace("[GIF 블록 스캔] 완료.");
        resolve({ errors, metadata, skipped: false });
      };
      reader.onerror = () =>
        resolve({
          errors: ["파일 읽기 중 오류"],
          metadata: [],
          skipped: false,
        });
      reader.readAsArrayBuffer(file);
    });
  }

  /**
   * @description GIF의 데이터 서브 블록들을 건너뛰고 다음 블록의 시작 위치를 반환합니다.
   * @private
   */
  static _skipSubBlocks(bytes, startIndex) {
    let i = startIndex;
    while (i < bytes.length && bytes[i] !== 0x00) {
      const blockSize = bytes[i];
      i += blockSize + 1;
    }
    return i + 1; // 0x00 종결자 다음 위치
  }

  /**
   * @description GIF의 데이터 서브 블록들에서 실제 데이터를 추출합니다.
   * @private
   */
  static _extractSubBlockData(bytes, startIndex) {
    const dataChunks = [];
    let i = startIndex;
    while (i < bytes.length && bytes[i] !== 0x00) {
      const blockSize = bytes[i];
      dataChunks.push(bytes.slice(i + 1, i + 1 + blockSize));
      i += blockSize + 1;
    }
    // Blob으로 합쳐서 처리하는 것이 큰 데이터에 효율적일 수 있으나, 여기서는 단순화
    const totalLength = dataChunks.reduce(
      (sum, chunk) => sum + chunk.length,
      0
    );
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of dataChunks) {
      result.set(chunk, offset);
      offset += chunk.length;
    }
    return result;
  }
}
/**
 * @file sfMetaScannerSvg.js
 * @description SVG 파일의 텍스트 내용을 스캔하고 분석하는 전문 스캐너 클래스입니다.
 *
 * 이 클래스는 SVG 파일(XML 기반 텍스트)을 읽어 잠재적인 보안 위협 요소(예: <script> 태그)를
 * 탐지하고, <metadata> 태그의 내용을 추출하는 기능을 제공합니다.
 */
class sfMetaScannerSvg {
  /**
   * @description SVG 파일을 스캔하여 분석 결과를 반환합니다.
   * @static
   * @param {File} file - 분석할 File 객체.
   * @param {sfImageSanitizerLog} [logger] - 로그를 기록할 로거 인스턴스.
   * @returns {Promise<object>} 스캔 결과({ errors, metadata, skipped })를 담은 Promise.
   */
  static scan(file, logger) {
    return new Promise((resolve) => {
      if (logger) logger.trace("[SVG 콘텐츠 스캔] 시작...");
      const reader = new FileReader();
      reader.onload = (e) => {
        const text = e.target.result;
        const errors = [];
        const metadata = [];

        // 1. 보안 위협 검사: <script> 태그 존재 여부 확인
        if (text.toLowerCase().includes("<script")) {
          const message =
            "파일 내부에 잠재적으로 위험한 <script> 태그가 존재합니다.";
          if (logger) logger.trace(` -> 보안 위협 발견: ${message}`);
          errors.push(message);
        }

        // 2. 메타데이터 추출: <metadata> 태그 내용 확인
        const metadataMatch = text.match(
          /<metadata[^>]*>([\s\S]*?)<\/metadata>/i
        );
        if (metadataMatch && metadataMatch[1].trim()) {
          const extractedMeta = metadataMatch[1].trim();
          if (logger) logger.trace(` -> <metadata> 태그 발견, 내용 추출.`);
          const value =
            extractedMeta.length > 200
              ? extractedMeta.substring(0, 200) + "..."
              : extractedMeta;
          metadata.push({ key: "SVG Metadata", value });
        }

        if (logger) logger.trace("[SVG 콘텐츠 스캔] 완료.");
        resolve({ errors, metadata, skipped: false });
      };
      reader.onerror = () =>
        resolve({
          errors: ["파일 읽기 중 오류"],
          metadata: [],
          skipped: false,
        });
      // SVG는 텍스트 파일이므로 readAsText를 사용합니다.
      reader.readAsText(file);
    });
  }
}
/**
 * @file sfMetaScannerWebp.js
 * @description WebP 파일의 모든 청크(Chunk)를 스캔하고 식별하는 전문 스캐너 클래스입니다.
 *
 * WebP는 RIFF 컨테이너 형식을 기반으로 하며, 'RIFF' 헤더와 'WEBP' 식별자,
 * 그리고 다양한 청크들로 구성됩니다. 이 스캐너는 그 구조를 해부하여 보여줍니다.
 */
class sfMetaScannerWebp {
  /**
   * @description 주요 WebP 청크 타입(FourCC) 정보입니다.
   */
  static WEBP_CHUNK_TYPES = {
    "VP8 ": "Lossy Image Data (손실 압축 이미지 데이터)",
    VP8L: "Lossless Image Data (무손실 압축 이미지 데이터)",
    VP8X: "Extended File Features (애니메이션, 투명도, 메타데이터 등 확장 기능)",
    ANIM: "Animation Parameters (애니메이션 전역 정보)",
    ANMF: "Animation Frame (개별 애니메이션 프레임)",
    ALPH: "Alpha Channel Data (알파 채널/투명도 정보)",
    ICCP: "ICC Profile (색상 프로파일)",
    EXIF: "EXIF Metadata (EXIF 메타데이터)",
    "XMP ": "XMP Metadata (XMP 메타데이터)",
  };

  /**
   * @description WebP 파일을 스캔하여 발견된 모든 청크의 목록을 반환합니다.
   * @static
   */
  static scan(file, logger) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        if (logger) logger.trace("[WebP 청크 스캔] 시작...");
        const bytes = new Uint8Array(e.target.result);
        const view = new DataView(bytes.buffer);
        const metadata = [];
        const errors = [];
        let i = 0;

        // 1. RIFF 헤더 검증
        const riffHeader = new TextDecoder().decode(bytes.slice(i, i + 4));
        const webpId = new TextDecoder().decode(bytes.slice(i + 8, i + 12));
        if (riffHeader === "RIFF" && webpId === "WEBP") {
          metadata.push({ key: "RIFF/WEBP", value: "WebP Container Header" });
          i += 12; // 헤더(12바이트)를 건너뜁니다.
        } else {
          errors.push("유효한 WebP(RIFF) 파일 헤더가 아닙니다.");
          resolve({ errors, metadata, skipped: false });
          return;
        }

        // 2. 청크 루프
        while (i < bytes.length - 8) {
          // 최소 청크 헤더(8바이트) 크기 이상 남았을 때
          const chunkId = new TextDecoder().decode(bytes.slice(i, i + 4));
          // RIFF는 Little Endian을 사용합니다.
          const chunkSize = view.getUint32(i + 4, true);

          const description =
            this.WEBP_CHUNK_TYPES[chunkId] || "알 수 없는 청크";
          if (logger)
            logger.trace(
              `[WebP 청크 스캔] '${chunkId}' 청크 발견 at offset=${i}, 데이터 길이: ${chunkSize} bytes`
            );
          metadata.push({ key: chunkId, value: description });

          // 다음 청크의 시작 위치 계산
          let nextChunkPos = i + 8 + chunkSize;

          // [중요] RIFF 청크는 데이터 크기가 홀수일 경우, 1바이트 패딩(padding)을 추가합니다.
          if (chunkSize % 2 !== 0) {
            nextChunkPos++;
          }

          if (nextChunkPos <= i || nextChunkPos > bytes.length) {
            errors.push(
              `'${chunkId}' 청크의 길이가 비정상적이어서 스캔을 중단합니다.`
            );
            break;
          }
          i = nextChunkPos;
        }

        if (logger) logger.trace("[WebP 청크 스캔] 완료.");
        resolve({ errors, metadata, skipped: false });
      };
      reader.onerror = () =>
        resolve({
          errors: ["파일 읽기 중 오류"],
          metadata: [],
          skipped: false,
        });
      reader.readAsArrayBuffer(file);
    });
  }
}
/**
 * @file sfMetaScannerTiff.js
 * @description TIFF 파일의 IFD(Image File Directory)와 모든 태그를 스캔하는 전문 스캐너 클래스입니다.
 *
 * TIFF 파일은 헤더와 IFD(태그들의 목록)로 구성된 복잡한 구조를 가집니다.
 * 이 스캐너는 바이트 순서(Endianness)를 파악하고, IFD 오프셋을 따라가며 파일의 구조를 해부합니다.
 */
class sfMetaScannerTiff {
  /**
   * @description 주요 TIFF 태그 정보입니다. (전체 목록의 일부)
   */
  static TIFF_TAGS = {
    0x0100: { name: "ImageWidth", description: "이미지 너비" },
    0x0101: { name: "ImageLength", description: "이미지 높이 (세로)" },
    0x0102: { name: "BitsPerSample", description: "샘플 당 비트 수" },
    0x0103: { name: "Compression", description: "압축 방식" },
    0x0106: {
      name: "PhotometricInterpretation",
      description: "픽셀 구성 방식",
    },
    0x010f: { name: "Make", description: "제조사 정보" },
    0x0110: { name: "Model", description: "카메라 모델 정보" },
    0x0112: { name: "Orientation", description: "이미지 방향" },
    0x011a: { name: "XResolution", description: "수평 해상도" },
    0x011b: { name: "YResolution", description: "수직 해상도" },
    0x0131: { name: "Software", description: "사용된 소프트웨어" },
    0x0132: { name: "DateTime", description: "파일 변경 날짜/시간" },
    0x8769: { name: "ExifOffset", description: "EXIF IFD 오프셋" },
    0x8825: { name: "GPSInfo", description: "GPS IFD 오프셋" },
  };

  /**
   * @description TIFF 파일을 스캔하여 발견된 모든 태그의 목록을 반환합니다.
   * @static
   */
  static scan(file, logger) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        if (logger) logger.trace("[TIFF 태그 스캔] 시작...");
        const bytes = new Uint8Array(e.target.result);
        const view = new DataView(bytes.buffer);
        const metadata = [];
        const errors = [];

        if (bytes.length < 8) {
          errors.push(
            "파일이 너무 작아 유효한 TIFF 헤더를 포함할 수 없습니다."
          );
          resolve({ errors, metadata, skipped: true });
          return;
        }

        // 1. 헤더 분석: 바이트 순서(Endianness) 및 첫 IFD 오프셋 확인
        const byteOrderMarker = view.getUint16(0, false); // Endianness는 모르므로 일단 Big-Endian으로 읽음
        const isLittleEndian = byteOrderMarker === 0x4949; // 'II'
        const isBigEndian = byteOrderMarker === 0x4d4d; // 'MM'

        if (!isLittleEndian && !isBigEndian) {
          errors.push(
            "유효한 TIFF 바이트 순서 마커('II' 또는 'MM')를 찾을 수 없습니다."
          );
          resolve({ errors, metadata, skipped: false });
          return;
        }
        if (logger)
          logger.trace(
            ` -> 바이트 순서 감지: ${
              isLittleEndian ? "Little Endian (II)" : "Big Endian (MM)"
            }`
          );

        const magicNumber = view.getUint16(2, isLittleEndian);
        if (magicNumber !== 42) {
          errors.push(
            `유효하지 않은 TIFF Magic Number(${magicNumber}) 입니다. (기대값: 42)`
          );
          resolve({ errors, metadata, skipped: false });
          return;
        }

        let currentIfdOffset = view.getUint32(4, isLittleEndian);
        if (logger) logger.trace(` -> 첫 번째 IFD 오프셋: ${currentIfdOffset}`);
        let ifdCount = 0;

        // 2. IFD 루프: 다음 IFD 오프셋이 0이 아닐 때까지 반복
        while (currentIfdOffset !== 0) {
          ifdCount++;
          if (logger)
            logger.trace(
              `[IFD #${ifdCount}] 스캔 시작 at offset=${currentIfdOffset}`
            );
          metadata.push({
            key: `IFD #${ifdCount}`,
            value: `Directory at offset ${currentIfdOffset}`,
          });

          if (currentIfdOffset + 2 > bytes.length) {
            errors.push(`IFD #${ifdCount} 오프셋이 파일 크기를 벗어납니다.`);
            break;
          }

          const entryCount = view.getUint16(currentIfdOffset, isLittleEndian);
          if (logger) logger.trace(` -> 태그 개수: ${entryCount}`);

          let entryOffset = currentIfdOffset + 2;

          // 3. 태그 루프: IFD 내의 모든 태그(Entry)를 순회
          for (let i = 0; i < entryCount; i++) {
            const tagId = view.getUint16(entryOffset, isLittleEndian);
            const tagInfo = this.TIFF_TAGS[tagId] || {
              name: `Unknown Tag (0x${tagId.toString(16)})`,
              description: "",
            };

            metadata.push({ key: tagInfo.name, value: tagInfo.description });
            entryOffset += 12; // 각 태그 엔트리는 12바이트
          }

          // 다음 IFD 오프셋을 읽어 루프를 계속할지 결정
          currentIfdOffset = view.getUint32(entryOffset, isLittleEndian);
          if (logger && currentIfdOffset !== 0)
            logger.trace(` -> 다음 IFD 오프셋: ${currentIfdOffset}`);
        }

        if (logger) logger.trace("[TIFF 태그 스캔] 완료.");
        resolve({ errors, metadata, skipped: false });
      };
      reader.onerror = () =>
        resolve({ errors: ["파일 읽기 중 오류"], metadata, skipped: false });
      reader.readAsArrayBuffer(file);
    });
  }
}
/**
 * @file sfMetaScannerBmp.js
 * @description BMP(Bitmap) 파일의 헤더 정보를 스캔하고 분석하는 전문 스캐너 클래스입니다.
 *
 * 이 클래스는 BMP 파일의 파일 헤더와 정보 헤더(DIB header)를 분석하여
 * 이미지의 크기, 색상 깊이, 압축 방식 등의 핵심 정보를 추출합니다.
 */
class sfMetaScannerBmp {
  /**
   * @description BMP 압축 방식 코드에 대한 설명입니다.
   */
  static BMP_COMPRESSION_METHODS = {
    0: "BI_RGB (압축 없음)",
    1: "BI_RLE8 (8-bit Run-Length Encoding)",
    2: "BI_RLE4 (4-bit Run-Length Encoding)",
    3: "BI_BITFIELDS (Bitfields)",
    4: "BI_JPEG (JPEG 이미지)",
    5: "BI_PNG (PNG 이미지)",
  };

  /**
   * @description BMP 파일을 스캔하여 분석 결과를 반환합니다.
   * @static
   */
  static scan(file, logger) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        if (logger) logger.trace("[BMP 헤더 스캔] 시작...");
        const bytes = new Uint8Array(e.target.result);
        const view = new DataView(bytes.buffer);
        const metadata = [];
        const errors = [];

        if (bytes.length < 54) {
          // 최소 헤더 크기 (파일 헤더 14 + 정보 헤더 40)
          errors.push("파일이 너무 작아 유효한 BMP 헤더를 포함할 수 없습니다.");
          resolve({ errors, metadata, skipped: true });
          return;
        }

        // 1. 파일 헤더 분석 (14 bytes)
        const magic = new TextDecoder().decode(bytes.slice(0, 2));
        if (magic === "BM") {
          metadata.push({ key: "Magic Number", value: `'BM' (Bitmap)` });
        } else {
          errors.push("유효한 BMP Magic Number('BM')가 아닙니다.");
          resolve({ errors, metadata, skipped: false });
          return;
        }
        // BMP는 Little Endian을 사용합니다.
        const fileSize = view.getUint32(2, true);
        const pixelDataOffset = view.getUint32(10, true);
        metadata.push({
          key: "File Size",
          value: `${fileSize.toLocaleString()} bytes`,
        });
        metadata.push({
          key: "Pixel Data Offset",
          value: `시작 위치 ${pixelDataOffset}`,
        });

        // 2. 정보 헤더(DIB Header) 분석
        const dibHeaderSize = view.getUint32(14, true);
        metadata.push({
          key: "Info Header Size",
          value: `${dibHeaderSize} bytes`,
        });

        const width = view.getInt32(18, true);
        const height = view.getInt32(22, true);
        metadata.push({ key: "Image Width", value: `${width} pixels` });
        metadata.push({ key: "Image Height", value: `${height} pixels` });

        const bpp = view.getUint16(28, true);
        metadata.push({ key: "Bits Per Pixel", value: `${bpp}-bit` });

        const compressionCode = view.getUint32(30, true);
        const compressionMethod =
          this.BMP_COMPRESSION_METHODS[compressionCode] || "알 수 없음";
        metadata.push({
          key: "Compression",
          value: `${compressionMethod} (코드: ${compressionCode})`,
        });

        // 3. 색상 테이블 존재 여부 추론
        if (bpp <= 8) {
          metadata.push({
            key: "Color Table",
            value: "색상 테이블(팔레트)이 존재할 가능성이 높음",
          });
        }

        if (logger) logger.trace("[BMP 헤더 스캔] 완료.");
        resolve({ errors, metadata, skipped: false });
      };
      reader.onerror = () =>
        resolve({ errors: ["파일 읽기 중 오류"], metadata, skipped: false });
      reader.readAsArrayBuffer(file);
    });
  }
}
/**
 * @file sfMetaScannerIco.js
 * @description ICO(Icon) 파일의 헤더와 디렉토리 엔트리를 스캔하는 전문 스캐너 클래스입니다.
 *
 * 이 클래스는 ICO 파일이 내부에 여러 이미지를 담는 컨테이너라는 점에 착안하여,
 * 헤더를 분석해 이미지 개수를 파악하고 각 이미지의 속성(크기, 색상 등)을 순차적으로 보여줍니다.
 */
class sfMetaScannerIco {
  /**
   * @description ICO 파일을 스캔하여 분석 결과를 반환합니다.
   * @static
   */
  static scan(file, logger) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        if (logger) logger.trace("[ICO 구조 스캔] 시작...");
        const bytes = new Uint8Array(e.target.result);
        const view = new DataView(bytes.buffer);
        const metadata = [];
        const errors = [];

        if (bytes.length < 6) {
          // 최소 헤더 크기
          errors.push("파일이 너무 작아 유효한 ICO 헤더를 포함할 수 없습니다.");
          resolve({ errors, metadata, skipped: true });
          return;
        }

        // 1. 헤더 분석 (6 bytes)
        // ICO 포맷은 Little Endian을 사용합니다.
        const reserved = view.getUint16(0, true);
        const imageType = view.getUint16(2, true);
        const imageCount = view.getUint16(4, true);

        if (reserved !== 0 || imageType !== 1) {
          errors.push("유효한 ICO 파일 시그니처가 아닙니다.");
          resolve({ errors, metadata, skipped: false });
          return;
        }
        metadata.push({ key: "ICO Header", value: "Windows Icon Resource" });
        metadata.push({
          key: "Image Count",
          value: `${imageCount}개의 이미지가 포함됨`,
        });
        if (logger) logger.trace(` -> 이미지 개수 확인: ${imageCount}`);

        // 2. 디렉토리 엔트리 분석 (각 16 bytes)
        for (let i = 0; i < imageCount; i++) {
          const entryOffset = 6 + i * 16;
          if (entryOffset + 16 > bytes.length) {
            errors.push(
              `이미지 #${i + 1}의 디렉토리 엔트리가 파일 크기를 벗어납니다.`
            );
            break;
          }

          if (logger)
            logger.trace(
              `[ICO Directory Entry #${i + 1}] 스캔 at offset=${entryOffset}`
            );

          let width = view.getUint8(entryOffset);
          let height = view.getUint8(entryOffset + 1);
          // ICO 명세: 너비/높이가 0이면 256을 의미합니다.
          if (width === 0) width = 256;
          if (height === 0) height = 256;

          const bpp = view.getUint16(entryOffset + 6, true);
          const sizeInBytes = view.getUint32(entryOffset + 8, true);
          const dataOffset = view.getUint32(entryOffset + 12, true);

          const description = `${width}x${height}, ${bpp}-bit, ${sizeInBytes.toLocaleString()} bytes at offset ${dataOffset}`;
          metadata.push({ key: `Image #${i + 1}`, value: description });
        }

        if (logger) logger.trace("[ICO 구조 스캔] 완료.");
        resolve({ errors, metadata, skipped: false });
      };
      reader.onerror = () =>
        resolve({ errors: ["파일 읽기 중 오류"], metadata, skipped: false });
      reader.readAsArrayBuffer(file);
    });
  }
}
/**
 * @file sfMetaScannerAvif.js
 * @description AVIF 파일의 ISOBMFF 박스(Box) 구조를 스캔하는 전문 스캐너 클래스입니다.
 *
 * AVIF 파일은 MP4와 동일한 ISOBMFF 컨테이너를 사용하며, '박스'라는 단위로 구성됩니다.
 * 이 스캐너는 각 박스를 순차적으로 식별하여 파일의 전체 구조를 보여줍니다.
 */
class sfMetaScannerAvif {
  /**
   * @description 주요 AVIF/ISOBMFF 박스 타입(FourCC) 정보입니다.
   */
  static AVIF_BOX_TYPES = {
    ftyp: "File Type Box (파일 형식 및 호환성 정보)",
    meta: "Meta Box (메타데이터 컨테이너)",
    hdlr: "Handler Box (메타 박스 내 데이터 종류 선언)",
    pitm: "Primary Item Reference Box (기본 이미지 항목 ID)",
    iloc: "Item Location Box (이미지 데이터 위치 정보)",
    iinf: "Item Info Box (이미지 항목 정보)",
    iprp: "Item Properties Box (이미지 속성 컨테이너)",
    ipco: "Item Property Container Box",
    ispe: "Image Spatial Extents (이미지 너비/높이)",
    pixi: "Pixel Information (픽셀당 비트 수)",
    av1C: "AV1 Codec Configuration (AV1 코덱 설정)",
    colr: "Colour Information Box (색상 정보)",
    grid: "Image Grid (격자 이미지 레이아웃)",
    mdat: "Media Data Box (실제 압축 이미지 데이터)",
  };

  /**
   * @description AVIF 파일을 스캔하여 발견된 모든 박스의 목록을 반환합니다.
   * @static
   */
  static scan(file, logger) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        if (logger) logger.trace("[AVIF 박스 스캔] 시작...");
        const bytes = new Uint8Array(e.target.result);
        const view = new DataView(bytes.buffer);
        const metadata = [];
        const errors = [];
        let i = 0;

        // ISOBMFF 박스 루프
        while (i < bytes.length - 8) {
          // 최소 박스 헤더(8바이트) 크기
          // ISOBMFF는 Big Endian을 사용합니다.
          const boxSize = view.getUint32(i, false);
          const boxType = new TextDecoder().decode(bytes.slice(i + 4, i + 8));

          const description = this.AVIF_BOX_TYPES[boxType] || "알 수 없는 박스";
          if (logger)
            logger.trace(
              `[AVIF 박스 스캔] '${boxType}' 박스 발견 at offset=${i}, 크기: ${boxSize} bytes`
            );
          metadata.push({ key: boxType, value: description });

          // ispe 박스에서 너비와 높이 정보를 직접 추출하여 보여줍니다.
          if (boxType === "ispe" && boxSize >= 16) {
            const width = view.getUint32(i + 8, false);
            const height = view.getUint32(i + 12, false);
            metadata[metadata.length - 1].value += ` - ${width}x${height}`;
          }

          let nextBoxPos = i + boxSize;

          if (boxSize === 0) {
            // 박스 크기가 0이면 파일 끝까지를 의미
            if (logger)
              logger.trace(" -> 박스 크기가 0이므로 스캔을 종료합니다.");
            break;
          }
          if (boxSize === 1) {
            // 64비트 크기 필드 사용 (현재는 지원하지 않고 건너뜀)
            if (i + 16 > bytes.length) break;
            // JavaScript는 64비트 정수를 안전하게 다루기 어려우므로 일단은 스캔을 중단합니다.
            errors.push(
              `64비트 크기의 '${boxType}' 박스는 현재 지원하지 않습니다.`
            );
            break;
          }

          if (nextBoxPos <= i || nextBoxPos > bytes.length) {
            errors.push(
              `'${boxType}' 박스의 크기가 비정상적이어서 스캔을 중단합니다.`
            );
            break;
          }
          i = nextBoxPos;
        }

        if (logger) logger.trace("[AVIF 박스 스캔] 완료.");
        resolve({ errors, metadata, skipped: false });
      };
      reader.onerror = () =>
        resolve({ errors: ["파일 읽기 중 오류"], metadata, skipped: false });
      reader.readAsArrayBuffer(file);
    });
  }
}
/**
 * @file sfMetaScannerHeic.js
 * @description HEIC 파일의 ISOBMFF 박스(Box) 구조를 스캔하는 전문 스캐너 클래스입니다.
 *
 * HEIC 파일은 AVIF와 마찬가지로 ISOBMFF 컨테이너를 사용하며, '박스'라는 단위로 구성됩니다.
 * 이 스캐너는 각 박스를 순차적으로 식별하여 파일의 전체 구조를 보여줍니다.
 */
class sfMetaScannerHeic {
  /**
   * @description 주요 HEIC/ISOBMFF 박스 타입(FourCC) 정보입니다.
   */
  static HEIC_BOX_TYPES = {
    ftyp: "File Type Box (HEIC 형식 및 호환성 정보)",
    meta: "Meta Box (메타데이터 컨테이너)",
    hdlr: "Handler Box (메타 박스 내 데이터 종류 선언)",
    pitm: "Primary Item Reference Box (기본 이미지 항목 ID)",
    iloc: "Item Location Box (이미지 데이터 위치 정보)",
    iinf: "Item Info Box (이미지 항목 정보)",
    iprp: "Item Properties Box (이미지 속성 컨테이너)",
    ipco: "Item Property Container Box",
    ispe: "Image Spatial Extents (이미지 너비/높이)",
    pixi: "Pixel Information (픽셀당 비트 수)",
    hvcC: "HEVC Decoder Configuration (HEVC 코덱 설정)", // HEIC의 핵심
    colr: "Colour Information Box (색상 정보)",
    grid: "Image Grid (격자 이미지 레이아웃)",
    mdat: "Media Data Box (실제 압축 이미지 데이터)",
  };

  /**
   * @description HEIC 파일을 스캔하여 발견된 모든 박스의 목록을 반환합니다.
   * @static
   */
  static scan(file, logger) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        if (logger) logger.trace("[HEIC 박스 스캔] 시작...");
        const bytes = new Uint8Array(e.target.result);
        const view = new DataView(bytes.buffer);
        const metadata = [];
        const errors = [];
        let i = 0;

        while (i < bytes.length - 8) {
          const boxSize = view.getUint32(i, false);
          const boxType = new TextDecoder().decode(bytes.slice(i + 4, i + 8));

          const description = this.HEIC_BOX_TYPES[boxType] || "알 수 없는 박스";
          if (logger)
            logger.trace(
              `[HEIC 박스 스캔] '${boxType}' 박스 발견 at offset=${i}, 크기: ${boxSize} bytes`
            );
          metadata.push({ key: boxType, value: description });

          if (boxType === "ispe" && boxSize >= 16) {
            const width = view.getUint32(i + 8, false);
            const height = view.getUint32(i + 12, false);
            metadata[metadata.length - 1].value += ` - ${width}x${height}`;
          }

          if (boxType === "ftyp" && boxSize >= 12) {
            const majorBrand = new TextDecoder().decode(
              bytes.slice(i + 8, i + 12)
            );
            metadata[
              metadata.length - 1
            ].value += ` - Major Brand: ${majorBrand}`;
          }

          let nextBoxPos = i + boxSize;

          if (boxSize === 0) {
            if (logger)
              logger.trace(" -> 박스 크기가 0이므로 스캔을 종료합니다.");
            break;
          }
          if (boxSize === 1) {
            errors.push(
              `64비트 크기의 '${boxType}' 박스는 현재 지원하지 않습니다.`
            );
            break;
          }

          if (nextBoxPos <= i || nextBoxPos > bytes.length) {
            errors.push(
              `'${boxType}' 박스의 크기가 비정상적이어서 스캔을 중단합니다.`
            );
            break;
          }
          i = nextBoxPos;
        }

        if (logger) logger.trace("[HEIC 박스 스캔] 완료.");
        resolve({ errors, metadata, skipped: false });
      };
      reader.onerror = () =>
        resolve({ errors: ["파일 읽기 중 오류"], metadata, skipped: false });
      reader.readAsArrayBuffer(file);
    });
  }
}
/**
 * @file sfMetaScannerJp2.js
 * @description JPEG 2000 (JP2) 파일의 박스(Box) 구조를 스캔하는 전문 스캐너 클래스입니다.
 *
 * JP2 파일은 고유한 시그니처 박스로 시작하고, 그 뒤에 ISOBMFF와 유사한 박스들이 이어지는 구조입니다.
 * 이 스캐너는 이 구조를 해부하여 파일의 구성 요소를 보여줍니다.
 */
class sfMetaScannerJp2 {
  /**
   * @description 주요 JP2 박스 타입(FourCC) 정보입니다.
   */
  static JP2_BOX_TYPES = {
    "jP  ": "JPEG 2000 Signature Box (파일 시그니처)",
    ftyp: "File Type Box (파일 형식 및 호환성 정보)",
    jp2h: "JP2 Header Box (모든 헤더 정보를 담는 상위 박스)",
    ihdr: "Image Header Box (이미지 너비, 높이 등 핵심 정보)",
    colr: "Colour Specification Box (색상 정보)",
    "res ": "Resolution Box (해상도 정보)",
    jp2c: "Contiguous Codestream Box (실제 압축 이미지 데이터)",
  };

  /**
   * @description JP2 파일을 스캔하여 발견된 모든 박스의 목록을 반환합니다.
   * @static
   */
  static scan(file, logger) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        if (logger) logger.trace("[JPEG 2000 박스 스캔] 시작...");
        const bytes = new Uint8Array(e.target.result);
        const view = new DataView(bytes.buffer);
        const metadata = [];
        const errors = [];
        let i = 0;

        // 1. JPEG 2000 필수 시그니처 박스 검증 (12 bytes)
        const SIGNATURE = [
          0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20, 0x0d, 0x0a, 0x87,
          0x0a,
        ];
        if (
          bytes.length < 12 ||
          !SIGNATURE.every((val, idx) => val === bytes[idx])
        ) {
          errors.push(
            "유효한 JPEG 2000 시그니처 박스가 파일의 시작 부분에 없습니다."
          );
          resolve({ errors, metadata, skipped: false });
          return;
        }
        metadata.push({ key: "jP  ", value: this.JP2_BOX_TYPES["jP  "] });
        i += 12;

        // 2. 나머지 박스 루프
        while (i < bytes.length - 8) {
          const boxSize = view.getUint32(i, false);
          const boxType = new TextDecoder().decode(bytes.slice(i + 4, i + 8));

          const description = this.JP2_BOX_TYPES[boxType] || "알 수 없는 박스";
          if (logger)
            logger.trace(
              `[JPEG 2000 박스 스캔] '${boxType}' 박스 발견 at offset=${i}, 크기: ${boxSize} bytes`
            );
          metadata.push({ key: boxType, value: description });

          // ihdr 박스에서 너비와 높이 정보를 직접 추출
          if (boxType === "ihdr" && boxSize >= 22) {
            const height = view.getUint32(i + 8, false);
            const width = view.getUint32(i + 12, false);
            metadata[metadata.length - 1].value += ` - ${width}x${height}`;
          }

          let nextBoxPos = i + boxSize;

          if (boxSize === 0) {
            if (logger)
              logger.trace(" -> 박스 크기가 0이므로 스캔을 종료합니다.");
            break;
          }
          if (boxSize === 1) {
            errors.push(
              `64비트 크기의 '${boxType}' 박스는 현재 지원하지 않습니다.`
            );
            break;
          }

          if (nextBoxPos <= i || nextBoxPos > bytes.length) {
            errors.push(
              `'${boxType}' 박스의 크기가 비정상적이어서 스캔을 중단합니다.`
            );
            break;
          }
          i = nextBoxPos;
        }

        if (logger) logger.trace("[JPEG 2000 박스 스캔] 완료.");
        resolve({ errors, metadata, skipped: false });
      };
      reader.onerror = () =>
        resolve({ errors: ["파일 읽기 중 오류"], metadata, skipped: false });
      reader.readAsArrayBuffer(file);
    });
  }
}
/**
 * @file sfMetadataAnalyzer.js
 * @description [최종 아키텍처] 파일 형식별 전문 스캐너를 호출하는 100% 순수 디스패처 클래스입니다.
 *
 * 이 클래스는 이제 어떤 형식의 분석 로직도 직접 수행하지 않으며,
 * 오직 올바른 전문가(sfMetaScanner[Format].js)에게 작업을 위임하는 책임만 가집니다.
 *
 * [예외]
 * JPEG의 EXIF 데이터 분석 로직은 외부 라이브러리(exif-js)에 대한 의존성 때문에
 * 이 파일 내에 헬퍼 함수 형태로 유지됩니다. 하지만 이 로직조차도 JPEG 전문 스캐너인
 * sfMetaScannerJpeg.js에 의해 호출되어 사용되므로, 이 클래스의 디스패처 역할은 일관되게 유지됩니다.
 *
 * @dependency exif.min.js
 * @dependency sfMetaScannerJpeg.js
 * @dependency sfMetaScannerPng.js
 * @dependency sfMetaScannerGif.js
 * @dependency sfMetaScannerSvg.js
 * @dependency sfMetaScannerWebp.js
 * @dependency sfMetaScannerTiff.js
 * @dependency sfMetaScannerBmp.js
 * @dependency sfMetaScannerIco.js
 * @dependency sfMetaScannerAvif.js
 * @dependency sfMetaScannerHeic.js
 * @dependency sfMetaScannerJp2.js
 */
class sfMetadataAnalyzer {
  /**
   * @description 파일 형식에 맞는 메타데이터 분석을 시작하는 메인 진입점 함수입니다.
   *              이 함수는 마치 전화 교환원처럼, 들어온 파일의 형식(format)을 보고
   *              가장 적절한 전문가(sfMetaScanner)에게 전화를 연결해주는 역할을 합니다.
   * @param {File} file - 분석할 File 객체.
   * @param {string | null} format - '파일 구조 분석' 단계에서 식별된 실제 파일 형식.
   * @param {sfImageSanitizerLog} [logger] - 상세한 분석 과정을 기록하기 위한 로거 인스턴스.
   * @returns {Promise<object>} 각 전문 스캐너가 반환하는 표준화된 분석 결과 객체.
   */
  async analyze(file, format, logger) {
    switch (format) {
      case "jpeg":
        // JPEG는 구조(마커)와 내용(EXIF)을 모두 분석하는 가장 복잡한 전문가를 호출합니다.
        return sfMetaScannerJpeg.scan(file, logger);
      case "png":
      case "apng":
        return sfMetaScannerPng.scan(file, logger);
      case "gif":
        return sfMetaScannerGif.scan(file, logger);
      case "svg":
        return sfMetaScannerSvg.scan(file, logger);
      case "webp":
        return sfMetaScannerWebp.scan(file, logger);
      case "tiff":
        return sfMetaScannerTiff.scan(file, logger);
      case "bmp":
        return sfMetaScannerBmp.scan(file, logger);
      case "ico":
        return sfMetaScannerIco.scan(file, logger);
      case "avif":
        return sfMetaScannerAvif.scan(file, logger);
      case "heic":
        return sfMetaScannerHeic.scan(file, logger);
      case "jpeg2000":
        return sfMetaScannerJp2.scan(file, logger);
      default:
        // 어떤 전문가와도 연결할 수 없는 경우, 분석을 지원하지 않음을 알립니다.
        return {
          errors: [],
          warnings: [],
          metadata: [],
          skipped: true,
          reason: `이 형식(${
            format || "알 수 없음"
          })은 현재 메타데이터 분석을 지원하지 않습니다.`,
        };
    }
  }
}
/**
 * @file sfImageSanitizerLog.js
 * @description [구조화 로깅 기능 추가] 중앙 집중식 로깅 클래스 파일입니다. (서비스 계층)
 *
 * 이 클래스는 애플리케이션 전체의 로그 메시지를 관리하고, 설정된 출력(UI)으로 전달합니다.
 *
 * [주요 업그레이드]
 * - 이제 모든 로그 함수(info, success 등)가 단순 문자열뿐만 아니라
 *   구조화된 객체({ key, value, details, rawData, ... })도 인자로 받을 수 있습니다.
 * - 객체가 전달되면, _formatStructuredLog 헬퍼를 통해 계층적인 로그 문자열을
 *   자동으로 생성하여 출력합니다. 이로써 로그 형식의 일관성을 보장하고,
 *   컨트롤러의 코드를 매우 깔끔하게 유지합니다.
 */
class sfImageSanitizerLog {
  /**
   * 로거 생성자입니다.
   * @param {object} [options={}] - 로거 설정을 위한 옵션 객체.
   * @param {boolean} [options.debugMode=false] - 디버그 모드를 활성화할지 여부.
   * @param {boolean} [options.deepDebugMode=false] - 심층 디버깅 모드를 활성화할지 여부.
   */
  constructor(options = {}) {
    this.debugMode = options.debugMode ?? false;
    this.deepDebugMode = options.deepDebugMode ?? false;
    this.outputCallback = null;
  }

  /**
   * 로그 메시지를 전달받을 콜백 함수를 등록(연결)합니다.
   * 이 함수는 로거와 UI 사이의 연결고리 역할을 하여, 서로를 직접 알 필요가 없게 만듭니다 (느슨한 결합).
   * @param {function | null} callback - 로그 객체({level, message})를 인자로 받는 콜백 함수.
   */
  setOutput(callback) {
    this.outputCallback = callback;
  }

  // --- 공개 로그 API ---
  // 이 함수들은 내부 _log 함수를 호출하는 편리한 래퍼(wrapper)입니다.
  info(msgOrObj) {
    this._log("info", msgOrObj);
  }
  success(msgOrObj) {
    this._log("success", msgOrObj);
  }
  error(msgOrObj) {
    this._log("error", msgOrObj);
  }
  warning(msgOrObj) {
    this._log("warning", msgOrObj);
  }
  notice(msgOrObj) {
    this._log("notice", msgOrObj);
  }
  debug(msgOrObj) {
    if (this.debugMode) this._log("debug", msgOrObj);
  }
  trace(msgOrObj) {
    if (this.deepDebugMode) this._log("trace", msgOrObj);
  }

  /**
   * @description Uint8Array를 보기 좋은 Hex 문자열로 변환하는 헬퍼 함수.
   * @param {Uint8Array} bytes - 변환할 바이트 배열.
   * @param {number} maxLength - 표시할 최대 바이트 수.
   * @returns {string} 변환된 Hex 문자열.
   * @private
   */
  _bytesToHexString(bytes, maxLength = 32) {
    if (!bytes) return "";
    const displayLength = Math.min(bytes.length, maxLength);
    let hexString = "";
    for (let i = 0; i < displayLength; i++) {
      hexString += bytes[i].toString(16).padStart(2, "0").toUpperCase() + " ";
    }
    if (bytes.length > maxLength) {
      hexString += "...";
    }
    return hexString.trim();
  }

  /**
   * @description [핵심 기능] 구조화된 객체를 사람이 읽기 좋은 계층적 문자열로 포맷팅합니다.
   *              이 함수가 바로 아름다운 보고서가 생성되는 곳입니다.
   * @param {object} logData - {key, value, hex, offset, length, details, rawData} 등의 속성을 가진 객체.
   * @private
   */
  _formatStructuredLog(logData) {
    // 레벨 1: 헤더 생성 (마커 종류, 이름, 위치, 크기 등)
    let header = `- [${logData.key}`;
    if (logData.hex) header += ` / ${logData.hex}`;
    header += `] ${logData.value}`;
    if (logData.offset !== undefined) {
      header += ` (위치: ${logData.offset}, 길이: ${
        logData.length || "N/A"
      } bytes)`;
    }

    let lines = [header];

    // 레벨 2: 상세 내용 (파싱된 결과)
    if (logData.details) {
      const indentedDetails = logData.details
        .split("\n")
        .map((line) => `  ${line}`)
        .join("\n");
      lines.push(indentedDetails);
    }

    return lines.join("\n"); // 여러 줄의 문자열로 반환
  }

  /**
   * 로그 객체를 생성하고, 등록된 출력 콜백과 개발자 콘솔 양쪽으로 전달하는 내부 메서드입니다.
   * @private
   */
  _log(level, msgOrObj) {
    let message;
    // 인자가 문자열이 아닌 객체일 경우, 포맷팅 함수를 호출합니다.
    if (
      typeof msgOrObj === "object" &&
      msgOrObj !== null &&
      !Array.isArray(msgOrObj)
    ) {
      message = this._formatStructuredLog(msgOrObj);
    } else {
      message = String(msgOrObj);
    }

    const logObject = {
      level: level,
      message: message,
      timestamp: new Date(),
    };

    // UI로 로그 전달
    if (this.outputCallback) {
      this.outputCallback(logObject);
    }

    // 개발자 콘솔로 로그 전달 (디버깅 편의성)
    switch (level) {
      case "success":
        console.info(`[SUCCESS] ${message}`);
        break;
      case "info":
        console.info(`[INFO] ${message}`);
        break;
      case "error":
        console.error(`[ERROR] ${message}`);
        break;
      case "warning":
        console.warn(`[WARNING] ${message}`);
        break;
      case "notice":
        console.log(`%c[NOTICE] ${message}`, "color: #999;");
        break;
      case "debug":
        console.log(`%c[DEBUG] ${message}`, "color: #888; font-style: italic;");
        break;
      case "trace":
        console.log(
          `%c[TRACE] ${message}`,
          "color: #6c757d; font-style: italic;"
        );
        break;
    }
  }
}
/**
 * @file sfImageSanitizerUI.js
 * @description UI 생성 및 제어 클래스 파일입니다. (뷰 계층)
 *
 * 이 클래스는 애플리케이션의 모든 DOM 요소 생성 및 조작을 전담합니다.
 * 컨트롤러(sfImageSanitizer.js)로부터 명령을 받아 화면을 그리고, 사용자의 상호작용을 감지합니다.
 *
 * [핵심 아키텍처]
 * - 캡슐화: 복잡한 UI 로직을 내부에 감추고, 외부에는 단순하고 명확한 명령 인터페이스만 제공합니다.
 * - 파일 기반 관리: `fileUINodes` Map을 사용하여 각 파일과 그에 해당하는 DOM 요소들을 1:1로 매핑하여
 *   정확하고 효율적으로 UI를 제어합니다.
 *
 * [네임스페이스]
 * - 모든 생성된 요소의 className에는 'sfImageSanitizer-' 접두사를 사용하여 CSS 충돌을 방지합니다.
 */
class sfImageSanitizerUI {
  /**
   * UI 클래스의 생성자입니다.
   * @param {object} [options={}] - UI 설정을 포함하는 옵션 객체.
   */
  constructor(options = {}) {
    const uiOptions = options.ui || {};

    /**
     * @property {Map<File, object>} fileUINodes
     * @description File 객체를 키로, 해당 파일의 모든 관련 DOM 요소 참조를 담은 객체를 값으로 갖는 Map.
     */
    this.fileUINodes = new Map();

    const mainContainer = document.querySelector(uiOptions.mainContainerId);
    if (!mainContainer)
      throw new Error(
        `메인 컨테이너(${uiOptions.mainContainerId})를 찾을 수 없습니다.`
      );
    if (uiOptions.dropZoneHeight)
      mainContainer.style.height = uiOptions.dropZoneHeight;

    this.resultsContainerEl = document.querySelector(
      uiOptions.resultsContainerId
    );
    if (!this.resultsContainerEl)
      throw new Error(
        `결과 컨테이너(${uiOptions.resultsContainerId})를 찾을 수 없습니다.`
      );

    this._createDropZoneUI(mainContainer);
  }

  /**
   * 기능: 드래그 앤 드롭 영역의 UI를 생성합니다. 애플리케이션 로드 시 한 번만 실행됩니다.
   * @private
   */
  _createDropZoneUI(container) {
    const dropZoneEl = document.createElement("div");
    dropZoneEl.className = "sfImageSanitizer-drop-zone";
    const dropZonePromptMessageEl = document.createElement("div");
    dropZonePromptMessageEl.className = "sfImageSanitizer-prompt-message";
    const dropZonePromptIconEl = document.createElement("i");
    dropZonePromptIconEl.className = "material-icons";
    dropZonePromptIconEl.textContent = "upload_file";
    const dropZonePromptTextMainEl = document.createElement("p");
    dropZonePromptTextMainEl.textContent =
      "스캔할 이미지 파일을 여기에 드래그 앤 드롭하세요";
    const dropZonePromptTextSubEl = document.createElement("p");
    dropZonePromptTextSubEl.textContent =
      "또는 이 영역을 클릭하여 파일을 선택하세요";
    dropZonePromptMessageEl.append(
      dropZonePromptIconEl,
      dropZonePromptTextMainEl,
      dropZonePromptTextSubEl
    );
    const fileInputEl = document.createElement("input");
    fileInputEl.type = "file";
    fileInputEl.className = "sfImageSanitizer-file-input";
    fileInputEl.accept = "image/*";
    fileInputEl.multiple = true;
    dropZoneEl.append(dropZonePromptMessageEl, fileInputEl);
    container.appendChild(dropZoneEl);
    this.dropZoneEl = dropZoneEl;
    this.fileInputEl = fileInputEl;
  }

  /**
   * 기능: 특정 파일을 위한 개별 결과 카드 UI를 동적으로 생성합니다.
   * @param {File} file - 이 UI 노드의 주인이 될 File 객체.
   */
  createResultNode(file) {
    const itemEl = document.createElement("div");
    itemEl.className = "sfImageSanitizer-result-item";
    const thumbnailEl = document.createElement("div");
    thumbnailEl.className = "sfImageSanitizer-result-thumbnail";
    const infoAreaEl = document.createElement("div");
    infoAreaEl.className = "sfImageSanitizer-result-info-area";
    const headerEl = document.createElement("div");
    headerEl.className = "sfImageSanitizer-progress-header";
    const fileNameEl = document.createElement("span");
    fileNameEl.className = "sfImageSanitizer-file-name";
    const fileSizeEl = document.createElement("span");
    fileSizeEl.className = "sfImageSanitizer-file-size";
    const resolutionEl = document.createElement("span");
    resolutionEl.className = "sfImageSanitizer-media-resolution";
    const headerRightGroup = document.createElement("div");
    headerRightGroup.className = "sfImageSanitizer-header-right-group";
    const fileInfoEl = document.createElement("span");
    fileInfoEl.className = "sfImageSanitizer-file-info";
    const downloadBtnEl = document.createElement("button");
    downloadBtnEl.className = "sfImageSanitizer-header-icon-btn download-btn";
    downloadBtnEl.type = "button";
    downloadBtnEl.title = "안전한 파일 다운로드";
    downloadBtnEl.textContent = "download";
    downloadBtnEl.style.display = "none";
    const closeBtnEl = document.createElement("button");
    closeBtnEl.className = "sfImageSanitizer-header-icon-btn close-btn";
    closeBtnEl.type = "button";
    closeBtnEl.title = "결과 닫기";
    closeBtnEl.textContent = "close";
    closeBtnEl.onclick = () => {
      itemEl.remove();
      this.fileUINodes.delete(file);
    };
    const collapseToggleBtnEl = document.createElement("button");
    collapseToggleBtnEl.className =
      "sfImageSanitizer-header-icon-btn sfImageSanitizer-collapse-toggle-btn";
    collapseToggleBtnEl.type = "button";
    collapseToggleBtnEl.title = "상세 정보 보기/숨기기";
    const iconExpand = document.createElement("span");
    iconExpand.className = "sfImageSanitizer-icon-expand material-icons";
    iconExpand.textContent = "expand_more";
    const iconCollapse = document.createElement("span");
    iconCollapse.className = "sfImageSanitizer-icon-collapse material-icons";
    iconCollapse.textContent = "expand_less";
    collapseToggleBtnEl.append(iconExpand, iconCollapse);
    headerRightGroup.append(
      fileInfoEl,
      downloadBtnEl,
      closeBtnEl,
      collapseToggleBtnEl
    );
    headerEl.append(fileNameEl, fileSizeEl, resolutionEl, headerRightGroup);
    const collapsibleContentEl = document.createElement("div");
    collapsibleContentEl.className =
      "sfImageSanitizer-collapsible-content collapsed";
    const progressBarContainerEl = document.createElement("div");
    progressBarContainerEl.className = "sfImageSanitizer-progress-bar";
    const progressBarFillEl = document.createElement("div");
    progressBarFillEl.className = "sfImageSanitizer-progress-bar-fill";
    progressBarContainerEl.appendChild(progressBarFillEl);
    const stepContainerEl = document.createElement("div");
    stepContainerEl.className = "sfImageSanitizer-step-container";
    collapsibleContentEl.append(progressBarContainerEl, stepContainerEl);
    const finalResultMessageEl = document.createElement("div");
    finalResultMessageEl.className = "sfImageSanitizer-final-result-message";
    collapseToggleBtnEl.onclick = () => {
      collapsibleContentEl.classList.toggle("collapsed");
      collapseToggleBtnEl.classList.toggle("expanded");
    };
    infoAreaEl.append(headerEl, collapsibleContentEl, finalResultMessageEl);
    itemEl.append(thumbnailEl, infoAreaEl);
    this.resultsContainerEl.appendChild(itemEl);
    this.fileUINodes.set(file, {
      itemEl,
      thumbnailEl,
      fileNameEl,
      fileSizeEl,
      fileInfoEl,
      progressBarFillEl,
      stepContainerEl,
      collapsibleContentEl,
      collapseToggleBtnEl,
      finalResultMessageEl,
      resolutionEl,
      downloadBtnEl,
    });
  }

  addAnalysisStep(file, stepName) {
    const nodes = this.fileUINodes.get(file);
    if (!nodes) return;
    const stepEl = document.createElement("div");
    stepEl.className = "sfImageSanitizer-analysis-step";
    const nameEl = document.createElement("h4");
    nameEl.className = "sfImageSanitizer-step-name";
    nameEl.textContent = stepName;
    const outputEl = document.createElement("div");
    outputEl.className = "sfImageSanitizer-step-output";
    const logsEl = document.createElement("div");
    logsEl.className = "sfImageSanitizer-step-logs";
    stepEl.append(nameEl, outputEl, logsEl);
    nodes.stepContainerEl.appendChild(stepEl);
    nodes.currentStepNodes = { outputEl, logsEl };
  }

  addLogContent(file, contentElement) {
    const nodes = this.fileUINodes.get(file);
    if (!nodes || !nodes.currentStepNodes) return;
    nodes.currentStepNodes.logsEl.appendChild(contentElement);
  }

  addLogMessage(file, message, type = "info") {
    const logEntryEl = document.createElement("p");
    logEntryEl.className = `sfImageSanitizer-log-${type}`;
    logEntryEl.textContent = `> ${message}`;
    logEntryEl.style.whiteSpace = "pre-wrap";
    this.addLogContent(file, logEntryEl);
  }

  setupProgressViews(file, fileName, fileCountText, fileSizeText) {
    const nodes = this.fileUINodes.get(file);
    if (!nodes) return;
    nodes.fileNameEl.textContent = fileName;
    nodes.fileSizeEl.textContent = fileSizeText;
    nodes.fileInfoEl.textContent = fileCountText;
    nodes.progressBarFillEl.style.width = "0%";
    nodes.stepContainerEl.innerHTML = "";
    nodes.resolutionEl.textContent = "";
    nodes.finalResultMessageEl.style.display = "none";
    nodes.downloadBtnEl.style.display = "none";
    nodes.collapsibleContentEl.classList.remove("collapsed");
    nodes.collapseToggleBtnEl.classList.add("expanded");
  }

  updateProgressBar(file, progress) {
    const nodes = this.fileUINodes.get(file);
    if (nodes) nodes.progressBarFillEl.style.width = `${progress * 100}%`;
  }

  updateHexPreview(file, chunkBytes, magicNumber) {
    const nodes = this.fileUINodes.get(file);
    if (!nodes || !nodes.currentStepNodes) return;
    const outputContainer = nodes.currentStepNodes.outputEl;
    outputContainer.innerHTML = "";
    const displayLength = Math.min(chunkBytes.length, 128);
    if (
      magicNumber &&
      magicNumber.length > 0 &&
      displayLength >= magicNumber.length
    ) {
      let highlightedHex = "";
      for (let i = 0; i < magicNumber.length; i++)
        highlightedHex += `<span style="color:#00ff00; font-weight:bold;">${chunkBytes[
          i
        ]
          .toString(16)
          .padStart(2, "0")
          .toUpperCase()}</span> `;
      for (let i = magicNumber.length; i < displayLength; i++)
        highlightedHex +=
          chunkBytes[i].toString(16).padStart(2, "0").toUpperCase() + " ";
      outputContainer.innerHTML = highlightedHex;
    } else {
      let hexString = "";
      for (let i = 0; i < displayLength; i++)
        hexString +=
          chunkBytes[i].toString(16).padStart(2, "0").toUpperCase() + " ";
      outputContainer.textContent = hexString;
    }
  }

  updateResolution(file, width, height) {
    const nodes = this.fileUINodes.get(file);
    if (nodes)
      nodes.resolutionEl.textContent =
        width && height ? `${width} x ${height}` : "";
  }

  showThumbnail(file) {
    const nodes = this.fileUINodes.get(file);
    if (!nodes) return;
    const img = document.createElement("img");
    img.src = URL.createObjectURL(file);
    img.onload = () => URL.revokeObjectURL(img.src);
    nodes.thumbnailEl.innerHTML = "";
    nodes.thumbnailEl.appendChild(img);
  }

  showFinalResultMessage(file, message, type) {
    const nodes = this.fileUINodes.get(file);
    if (!nodes) return;
    const msgEl = nodes.finalResultMessageEl;
    msgEl.textContent = message;
    msgEl.className = `sfImageSanitizer-final-result-message ${type}`;
    msgEl.style.display = "block";
  }

  showDownloadButton(file, downloadName) {
    const nodes = this.fileUINodes.get(file);
    if (nodes) {
      nodes.downloadBtnEl.onclick = () => {
        const url = URL.createObjectURL(file);
        const a = document.createElement("a");
        a.href = url;
        a.download = downloadName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      };
      nodes.downloadBtnEl.style.display = "flex";
    }
  }

  setFinalState(file, state) {
    const nodes = this.fileUINodes.get(file);
    if (nodes) nodes.itemEl.classList.add(state);
  }

  clearAllResults() {
    this.resultsContainerEl.innerHTML = "";
    this.fileUINodes.clear();
  }

  setDragOverState(isOver) {
    this.dropZoneEl.classList.toggle("drag-over", isOver);
  }
}
/**
 * @file sfImageSanitizerToolbar.js
 * @description 애플리케이션의 설정을 제어하는 툴바 UI 클래스 파일입니다. (뷰 계층)
 *
 * 이 클래스는 툴바 UI의 생성과 관리에 대한 모든 책임을 가집니다 (관심사 분리).
 * 툴바 내에서 발생하는 사용자 상호작용(예: 체크박스 클릭)을 감지하고,
 * `onOptionChange` 콜백을 통해 메인 컨트롤러(sfImageSanitizer.js)에 "옵션이 변경되었다"는 사실을 알립니다.
 *
 * [핵심 아키텍처]
 * - 이 클래스는 독립적인 컴포넌트로, 어떤 옵션이 어떤 동작을 유발하는지에 대해서는 알지 못합니다.
 * - 메인 컨트롤러와의 통신은 오직 `onOptionChange` 콜백을 통해서만 이루어집니다 (느슨한 결합).
 * - 새로운 설정 옵션을 추가하려면 `_createCheckboxOption` 헬퍼 메서드를 사용하면 되므로 유지보수가 용이합니다.
 *
 * [네임스페이스]
 * - 모든 생성된 요소의 className에는 'sfImageSanitizer-' 접두사를 사용하여 CSS 충돌을 방지합니다.
 */
class sfImageSanitizerToolbar {
  /**
   * 툴바 생성자입니다.
   * @param {string} containerSelector - 툴바 UI가 생성될 부모 요소의 CSS 선택자입니다.
   * @param {object} [initialOptions={}] - 툴바 UI의 초기 상태를 설정하기 위한 옵션 객체입니다.
   */
  constructor(containerSelector, initialOptions = {}) {
    /**
     * @property {HTMLElement} container - 툴바가 삽입될 부모 DOM 요소입니다.
     */
    this.container = document.querySelector(containerSelector);
    if (!this.container) {
      throw new Error(
        `툴바 컨테이너(${containerSelector})를 찾을 수 없습니다.`
      );
    }

    /**
     * @property {object} options - 툴바의 현재 상태를 저장하는 객체입니다.
     */
    this.options = initialOptions;

    /**
     * @property {?function} optionChangeCallback - 옵션이 변경될 때 호출될 외부 콜백 함수입니다.
     */
    this.optionChangeCallback = null;

    // 툴바의 모든 DOM 요소를 생성하고 조립하는 내부 메서드를 호출합니다.
    this._createToolbarUI();
  }

  /**
   * 기능: 외부(메인 컨트롤러)에서 옵션 변경 이벤트를 구독(subscribe)할 수 있도록 콜백 함수를 등록합니다.
   * @param {function} callback - 옵션 변경 시 호출될 함수입니다. (key, value)를 인자로 받습니다.
   */
  onOptionChange(callback) {
    this.optionChangeCallback = callback;
  }

  /**
   * 기능: 툴바의 전체 UI를 생성합니다.
   * @private
   */
  _createToolbarUI() {
    // 툴바의 최상위 컨테이너 요소 생성
    const toolbarEl = document.createElement("div");
    toolbarEl.className = "sfImageSanitizer-toolbar";

    // 툴바의 제목
    const titleEl = document.createElement("h4");
    titleEl.className = "sfImageSanitizer-toolbar-title";
    titleEl.textContent = "설정:";
    toolbarEl.appendChild(titleEl);

    // "파일 형식 자동변환" 체크박스 옵션 생성
    const autoConvertOption = this._createCheckboxOption(
      "autoConvertFormat",
      "파일 형식 자동변환",
      this.options.autoConvertFormat
    );
    toolbarEl.appendChild(autoConvertOption);

    // "디버그 모드" 체크박스 옵션 생성
    const debugModeOption = this._createCheckboxOption(
      "debugMode",
      "디버그 모드",
      this.options.debugMode
    );
    toolbarEl.appendChild(debugModeOption);

    // "심층 디버깅 모드" 체크박스 옵션 생성
    const deepDebugModeOption = this._createCheckboxOption(
      "deepDebugMode",
      "심층 디버깅",
      this.options.deepDebugMode
    );
    toolbarEl.appendChild(deepDebugModeOption);

    // 완성된 툴바를 HTML의 지정된 컨테이너에 삽입합니다.
    this.container.appendChild(toolbarEl);
  }

  /**
   * 기능: 체크박스 형태의 옵션을 생성하는 재사용 가능한 헬퍼 메서드입니다.
   * @param {string} key - 이 옵션을 식별하는 고유한 키 (예: 'debugMode').
   * @param {string} labelText - UI에 표시될 라벨 텍스트.
   * @param {boolean} isChecked - 체크박스의 초기 체크 상태.
   * @returns {HTMLElement} 생성된 옵션 UI 요소.
   * @private
   */
  _createCheckboxOption(key, labelText, isChecked) {
    const optionWrapper = document.createElement("div");
    optionWrapper.className = "sfImageSanitizer-toolbar-option";

    const label = document.createElement("label");
    label.className = "sfImageSanitizer-checkbox-label";

    // 실제 기능을 하는 보이지 않는 원본 체크박스
    const input = document.createElement("input");
    input.type = "checkbox";
    input.checked = isChecked;

    // CSS로 스타일링된 커스텀 체크박스 모양
    const customCheckbox = document.createElement("span");
    customCheckbox.className = "sfImageSanitizer-custom-checkbox";

    const text = document.createTextNode(labelText);

    // <label>로 감싸면 텍스트나 커스텀 체크박스 모양을 클릭해도 원본 input이 토글됩니다.
    label.append(input, customCheckbox, text);

    // 원본 체크박스의 상태가 변경될 때의 이벤트 리스너를 등록합니다.
    input.addEventListener("change", (e) => {
      const newValue = e.target.checked;
      this.options[key] = newValue; // 툴바의 내부 옵션 상태를 업데이트합니다.

      // 등록된 콜백 함수가 있다면 변경된 옵션의 키와 새로운 값을 전달하여 알립니다.
      if (this.optionChangeCallback) {
        this.optionChangeCallback(key, newValue);
      }
    });

    optionWrapper.appendChild(label);
    return optionWrapper;
  }
}
/**
 * @file sfImageSanitizer.js
 * @description 애플리케이션의 핵심 로직 컨트롤러(Controller) 클래스 파일입니다.
 */
class sfImageSanitizer {
  constructor(ui, toolbar, options = {}) {
    this.ui = ui;
    this.toolbar = toolbar;
    const logicOptions = options.logic || {};
    this.autoConvertFormat = logicOptions.autoConvertFormat ?? true;
    this.isAnalyzing = false;
    this.fileQueue = [];
    this.totalFiles = 0;
    this.processedFiles = 0;
    this.jpegCriticalMarkers = new Set(["SOI", "SOF0", "SOS", "EOI"]);
    this.logger = new sfImageSanitizerLog(logicOptions);
    this.metadataAnalyzer = new sfMetadataAnalyzer();
    this.logger.setOutput(null);

    this.analysisSteps = [
      {
        name: "파일 구조 분석",
        execute: (context) => {
          const onProgressCallback = (progress, chunkBytes) => {
            this.ui.updateProgressBar(context.file, progress);
            this.ui.updateHexPreview(context.file, chunkBytes, null);
          };
          return sfFileFormatAnalyzer.analyze(
            context.file,
            onProgressCallback,
            this.logger
          );
        },
        processResult: (result, context) => {
          context.formatResult = result;
          if (result.firstChunk)
            this.ui.updateHexPreview(
              context.file,
              result.firstChunk,
              result.magicNumber
            );
          if (result.dimensions)
            this.ui.updateResolution(
              context.file,
              result.dimensions.width,
              result.dimensions.height
            );
          if (result.structuralVerificationWarning) {
            context.hasWarnings = true;
            context.reasons.push(result.structuralVerificationWarning);
            this.logger.warning(result.structuralVerificationWarning);
          }
          if (result.isValid) {
            this.logger.info({
              key: "파일 형식",
              value: result.detectedFormat.toUpperCase(),
            });
            this.logger.success({
              key: "유효성",
              value: "파일 형식 및 확장자가 일치합니다.",
            });
          } else {
            const isMismatch =
              !result.isExtensionValid && result.detectedFormat;
            if (isMismatch && this.autoConvertFormat) {
              this.logger.warning({
                key: "자동 변환",
                value: `확장자(.${
                  result.extension
                })와 실제 형식(${result.detectedFormat.toUpperCase()})이 달라 자동 변환 후 분석을 계속합니다.`,
              });
              context.formatResult.isValid = true;
              context.correctedFileName = this._getCorrectedFileName(
                context.file.name,
                result.detectedFormat
              );
              context.hasWarnings = true;
            } else {
              context.isSafe = false;
              context.reasons.push(result.reason);
              this.logger.error({ key: "오류", value: result.reason });
            }
          }
        },
      },
      {
        name: "메타데이터 분석",
        execute: (context) =>
          this.metadataAnalyzer.analyze(
            context.file,
            context.formatResult.detectedFormat,
            this.logger
          ),
        processResult: (result, context) => {
          if (result.skipped) {
            this.logger.info(result.reason);
            return;
          }
          if (result.metadata && result.metadata.length > 0) {
            result.metadata.forEach((item) => {
              if (item.isMissing) {
                if (this.jpegCriticalMarkers.has(item.key)) {
                  this.logger.error(
                    `- [${item.key} / ${item.markerHex}] ${item.value} - 없음 (치명적 오류)`
                  );
                  context.isSafe = false;
                  context.reasons.push(
                    `${item.key} 마커가 누락되어 유효하지 않은 파일입니다.`
                  );
                } else {
                  this.logger.info(
                    `- [${item.key} / ${item.markerHex}] ${item.value} - 없음`
                  );
                }
                return;
              }
              let header = `- [${item.key}${
                item.markerHex ? ` / ${item.markerHex}` : ""
              }] ${item.value}`;
              if (item.offset !== undefined)
                header += ` (위치: ${item.offset}, 길이: ${
                  item.length || "N/A"
                } bytes)`;
              this.logger.info(header);
              if (item.details)
                this.logger.info(
                  `${item.details
                    .split("\n")
                    .map((line) => `  ${line}`)
                    .join("\n")}`
                );
              if (item.rawData && item.rawData.length > 0) {
                const dataBlockEl = document.createElement("div");
                dataBlockEl.className = "sfImageSanitizer-log-data-block";
                dataBlockEl.textContent = this._bytesToHexString(
                  item.rawData,
                  64
                );
                this.ui.addLogContent(context.file, dataBlockEl);
              }
            });
          }
          if (result.warnings && result.warnings.length > 0) {
            context.hasWarnings = true;
            context.reasons.push(...result.warnings);
            result.warnings.forEach((w) => this.logger.warning(w));
          }
          if (result.errors && result.errors.length > 0) {
            context.isSafe = false;
            context.reasons.push(...result.errors);
            result.errors.forEach((e) => this.logger.error(e));
          }
        },
      },
    ];
    this._attachEventListeners();
    this._attachToolbarListeners();
  }

  _handleLog(file, logObject) {
    this.ui.addLogMessage(file, logObject.message, logObject.level);
  }

  _attachEventListeners() {
    const { dropZoneEl, fileInputEl } = this.ui;
    if (!dropZoneEl || !fileInputEl) return;
    dropZoneEl.addEventListener(
      "click",
      () => !this.isAnalyzing && fileInputEl.click()
    );
    fileInputEl.addEventListener("change", (e) =>
      this.handleFiles(e.target.files)
    );
    dropZoneEl.addEventListener("dragenter", (e) => this._handleDrag(e, true));
    dropZoneEl.addEventListener("dragover", (e) => this._handleDrag(e));
    dropZoneEl.addEventListener("dragleave", (e) => this._handleDrag(e, false));
    dropZoneEl.addEventListener("drop", (e) => this._handleDrop(e));
  }

  _attachToolbarListeners() {
    this.toolbar.onOptionChange((key, value) => {
      if (key === "debugMode") this.logger.debugMode = value;
      if (key === "deepDebugMode") this.logger.deepDebugMode = value;
      if (key === "autoConvertFormat") this.autoConvertFormat = value;
    });
  }

  _handleDrag(e, isOver) {
    e.preventDefault();
    e.stopPropagation();
    if (typeof isOver === "boolean" && !this.isAnalyzing)
      this.ui.setDragOverState(isOver);
  }

  _handleDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    if (this.isAnalyzing) return;
    this.ui.setDragOverState(false);
    this.handleFiles(e.dataTransfer.files);
  }

  handleFiles(files) {
    if (!files || files.length === 0) return;
    if (!this.isAnalyzing) this.reset();
    this.fileQueue.push(...Array.from(files));
    this.totalFiles = this.fileQueue.length;
    this.ui.fileInputEl.value = "";
    if (!this.isAnalyzing) this.processFileQueue();
  }

  async processFileQueue() {
    this.isAnalyzing = true;
    while (this.fileQueue.length > 0) {
      const currentFile = this.fileQueue.shift();
      this.processedFiles++;
      this.ui.createResultNode(currentFile);
      const fileSizeText = `${this._formatFileSize(
        currentFile.size
      )} (${currentFile.size.toLocaleString("ko-KR")} bytes)`;
      this.ui.setupProgressViews(
        currentFile,
        currentFile.name,
        `파일 ${this.processedFiles} / ${this.totalFiles}`,
        fileSizeText
      );
      this.logger.setOutput(this._handleLog.bind(this, currentFile));

      const analysisContext = {
        file: currentFile,
        isSafe: true,
        hasWarnings: false,
        reasons: [],
        formatResult: null,
        correctedFileName: null,
      };

      for (const step of this.analysisSteps) {
        if (!analysisContext.isSafe) break;

        // [버그 수정] 'analysis'를 올바른 변수명인 'analysisContext'로 수정했습니다.
        if (
          step.name === "메타데이터 분석" &&
          !analysisContext.formatResult?.isValid
        )
          break;

        this.ui.addAnalysisStep(currentFile, step.name);
        try {
          const result = await step.execute(analysisContext);
          step.processResult(result, analysisContext);
        } catch (error) {
          analysisContext.isSafe = false;
          analysisContext.reasons.push(
            `'${step.name}' 단계에서 오류 발생: ${error.message}`
          );
          this.logger.error(
            `'${step.name}' 단계에서 예외 발생: ${error.message}`
          );
          break;
        }
      }

      this.ui.updateProgressBar(currentFile, 1.0);

      if (analysisContext.isSafe) {
        if (analysisContext.hasWarnings) {
          this.ui.showFinalResultMessage(
            currentFile,
            "분석 완료. 확인이 필요한 주의 항목이 있습니다.",
            "warning"
          );
          this.ui.setFinalState(currentFile, "warning");
        } else {
          this.ui.showFinalResultMessage(
            currentFile,
            "모든 분석 단계 통과. 안전한 파일입니다.",
            "success"
          );
          this.ui.setFinalState(currentFile, "success");
        }
        const downloadName =
          analysisContext.correctedFileName || currentFile.name;
        this.ui.showThumbnail(currentFile);
        this.ui.showDownloadButton(currentFile, downloadName);
      } else {
        this.ui.showFinalResultMessage(
          currentFile,
          "분석 실패. 잠재적 위험 요소가 발견되었습니다.",
          "error"
        );
        this.ui.setFinalState(currentFile, "error");
        this.ui.addAnalysisStep(currentFile, "상세 분석 결과");
        analysisContext.reasons.forEach((reason) => this.logger.error(reason));
      }
    }
    this.isAnalyzing = false;
  }

  _bytesToHexString(bytes, maxLength = 64) {
    if (!bytes) return "";
    const displayLength = Math.min(bytes.length, maxLength);
    let hexString = "";
    for (let i = 0; i < displayLength; i++) {
      hexString += bytes[i].toString(16).padStart(2, "0").toUpperCase() + " ";
    }
    if (bytes.length > maxLength) hexString += "...";
    return hexString.trim();
  }

  _getCorrectedFileName(originalName, newFormat) {
    const nameParts = originalName.split(".");
    nameParts.pop();
    return `${nameParts.join(".")}.${newFormat}`;
  }

  _formatFileSize(bytes) {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }

  reset() {
    this.isAnalyzing = false;
    this.fileQueue = [];
    this.totalFiles = 0;
    this.processedFiles = 0;
    this.ui.clearAllResults();
  }
}
