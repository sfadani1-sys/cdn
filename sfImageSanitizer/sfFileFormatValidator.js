// 파일이름: sfFileFormatValidator.js

/**
 * @file sfFileFormatValidator.js
 * @description [수정됨] 파일 형식 유효성 검사 유틸리티 클래스 파일입니다.
 * WebP와 같은 복합적인 시그니처를 정확하게 검증하도록 로직이 개선되었습니다.
 */
class sfFileFormatValidator {
  /**
   * [수정됨] 지원하는 파일 형식별 Magic Number 정의.
   * 각 형식의 시그니처가 더 명확하게 설명되었습니다.
   * @static
   */
  static magicNumbers = {
    // JPEG: SOI(FF D8) 마커와 다음 세그먼트 시작(FF)을 확인합니다.
    // 대부분의 JPEG 파일(JFIF, EXIF)은 이 패턴으로 시작합니다.
    jpeg: [0xff, 0xd8, 0xff],
    // PNG: 8바이트의 고정된 시그니처를 가집니다. (‰PNG...)
    png: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
    // GIF: 'GIF8' 문자열로 시작합니다. (뒤에 '7a' 또는 '89a'가 옴)
    gif: [0x47, 0x49, 0x46, 0x38],
  };

  /**
   * [핵심 변경] 파일의 바이너리 데이터를 검사하여 실제 파일 형식을 확인합니다.
   * WebP와 같이 여러 위치를 확인해야 하는 복잡한 형식 검증 로직이 추가되었습니다.
   * @static
   * @param {Uint8Array} uint8Array - 파일의 바이너리 데이터 (최소 12바이트 이상 권장).
   * @param {sfImageSanitizerLog} logger - 로그를 기록할 로거 인스턴스.
   * @returns {string|null} 감지된 파일 형식 또는 실패 시 null.
   */
  static getFormat(uint8Array, logger) {
    if (logger) logger.debug(`sfFileFormatValidator.getFormat() 호출`);

    // 1. 단순 시작 시그니처 기반의 형식을 먼저 검사합니다.
    for (const format in this.magicNumbers) {
      if (this._checkBytes(uint8Array, this.magicNumbers[format])) {
        if (logger) logger.debug(`Magic Number 일치: ${format}`);
        return format;
      }
    }

    // 2. [신규] 복합 시그니처 기반의 형식을 검사합니다 (WebP).
    // WebP는 offset 0에 'RIFF', offset 8에 'WEBP'가 있어야 합니다.
    const RIFF_SIGNATURE = [0x52, 0x49, 0x46, 0x46]; // 'RIFF'
    const WEBP_SIGNATURE = [0x57, 0x45, 0x42, 0x50]; // 'WEBP'
    if (
      this._checkBytes(uint8Array, RIFF_SIGNATURE, 0) &&
      this._checkBytes(uint8Array, WEBP_SIGNATURE, 8)
    ) {
      if (logger) logger.debug(`복합 시그니처 일치: webp`);
      return "webp";
    }

    // 3. 텍스트 기반 형식을 검사합니다 (SVG).
    try {
      const textDecoder = new TextDecoder("utf-8");
      const textStart = textDecoder
        .decode(uint8Array.slice(0, 256))
        .toLowerCase();
      if (textStart.includes("<svg")) {
        if (logger) logger.debug(`SVG 패턴('<svg') 발견됨`);
        return "svg";
      }
    } catch (e) {
      if (logger) logger.error(`SVG 텍스트 디코딩 실패: ${e.message}`);
    }

    if (logger) logger.debug("일치하는 파일 형식 없음.");
    return null;
  }

  /**
   * [핵심 변경] Uint8Array의 특정 오프셋(offset)부터 바이트 배열이 일치하는지 확인하는 헬퍼 메서드.
   * @private
   * @static
   * @param {Uint8Array} uint8Array - 파일의 바이너리 데이터.
   * @param {Array<number>} bytesToCheck - 비교할 바이트 배열.
   * @param {number} [offset=0] - 비교를 시작할 위치(인덱스).
   * @returns {boolean} 일치하면 true, 아니면 false.
   */
  static _checkBytes(uint8Array, bytesToCheck, offset = 0) {
    // 데이터가 비교할 길이보다 짧으면 즉시 false 반환
    if (uint8Array.length < offset + bytesToCheck.length) {
      return false;
    }
    // 지정된 오프셋부터 각 바이트를 순서대로 비교합니다.
    for (let i = 0; i < bytesToCheck.length; i++) {
      if (uint8Array[offset + i] !== bytesToCheck[i]) {
        return false;
      }
    }
    return true;
  }

  /**
   * 파일 이름에서 확장자를 추출하여 소문자로 반환합니다.
   * @static
   */
  static getExtension(fileName, logger) {
    if (logger)
      logger.debug(`sfFileFormatValidator.getExtension() 호출: ${fileName}`);
    const extension = fileName.split(".").pop().toLowerCase();
    if (logger) logger.debug(`추출된 확장자: '${extension}'`);
    return extension;
  }

  /**
   * 감지된 실제 파일 형식과 파일 확장자가 서로 유효하게 일치하는지 검사합니다.
   * @static
   */
  static isExtensionValid(detectedFormat, extension, logger) {
    if (logger)
      logger.debug(
        `sfFileFormatValidator.isExtensionValid() 호출: 형식='${detectedFormat}', 확장자='${extension}'`
      );

    if (!detectedFormat) {
      return false;
    }

    let isValid = false;
    switch (detectedFormat) {
      case "jpeg":
        isValid =
          extension === "jpg" || extension === "jpeg" || extension === "jfif";
        break;
      case "png":
        isValid = extension === "png";
        break;
      case "gif":
        isValid = extension === "gif";
        break;
      case "webp":
        isValid = extension === "webp";
        break;
      case "svg":
        isValid = extension === "svg";
        break;
      default:
        isValid = false;
    }
    if (logger) logger.debug(`확장자 검증 결과: ${isValid}`);
    return isValid;
  }
}
