// 파일이름: sfFileFormatAnalyzer.js

/**
 * @file sfFileFormatAnalyzer.js
 * @description 파일 형식 스트리밍 분석 클래스 파일입니다.
 *
 * File 객체의 ReadableStream을 사용하여 파일을 청크(chunk) 단위로 읽어들이면서
 * 실시간으로 파일 형식을 분석하고 진행 상황을 보고하는 기능을 제공합니다.
 * 모든 메서드는 인스턴스 생성 없이 직접 호출할 수 있는 static 메서드입니다.
 */
class sfFileFormatAnalyzer {
  /**
   * 파일 형식 분석을 스트림 방식으로 비동기적으로 수행합니다.
   * @static
   * @param {File} file - 분석할 File 객체.
   * @param {function} onProgress - 진행 상황을 보고하는 콜백 함수.
   *                                이 함수는 스트림에서 새로운 청크를 읽을 때마다 호출됩니다.
   *                                @param {number} progress - 전체 진행률 (0.0 ~ 1.0).
   *                                @param {Uint8Array} chunkBytes - 방금 읽어들인 바이트 청크.
   * @param {sfImageSanitizerLog} logger - 로그를 기록할 로거 인스턴스.
   * @returns {Promise<object>} 분석 결과를 담은 객체를 resolve하는 Promise.
   */
  static async analyze(file, onProgress, logger) {
    // ReadableStream을 지원하지 않는 구형 브라우저에 대한 예외 처리
    if (!file.stream) {
      const errorMsg = "브라우저가 파일 스트리밍을 지원하지 않습니다.";
      logger.error(errorMsg);
      return Promise.reject(errorMsg); // Promise를 reject하여 호출한 쪽에 에러를 알립니다.
    }

    logger.debug(
      `sfFileFormatAnalyzer.analyze() 호출: ${file.name}, 크기: ${file.size} bytes`
    );

    const fileSize = file.size;
    let bytesRead = 0;
    let firstChunk = null; // 파일 형식 분석에 사용할 첫 번째 청크
    let detectedFormat = null;

    // 파일로부터 ReadableStream을 가져옵니다.
    const stream = file.stream();
    const reader = stream.getReader();

    // `try...finally` 블록을 사용하여, 에러 발생 여부와 관계없이 항상 스트림을 해제하도록 보장합니다.
    try {
      // 스트림이 끝날 때까지 (done === true) 계속해서 청크를 읽습니다.
      while (true) {
        // `await reader.read()`: 다음 데이터 청크가 도착할 때까지 비동기적으로 기다립니다.
        const { done, value } = await reader.read(); // `value`는 Uint8Array 형태의 바이트 청크입니다.

        if (done) {
          logger.debug("파일 스트림 읽기 완료.");
          break; // 스트림이 모두 소진되었으면 루프를 종료합니다.
        }

        logger.debug(`청크 수신: ${value.length} bytes`);

        // [핵심 로직] 첫 번째 청크일 경우에만 파일 형식 분석을 수행합니다.
        // 파일 형식은 보통 파일의 가장 앞부분에 명시되어 있기 때문입니다.
        if (!firstChunk) {
          firstChunk = value; // 첫 번째 청크 저장
          logger.debug("첫 번째 청크 수신, 파일 형식 검증 시작...");
          // Validator를 사용하여 파일의 실제 형식을 감지하고, 로거를 전달합니다.
          detectedFormat = sfFileFormatValidator.getFormat(firstChunk, logger);
          logger.info(`파일 형식 감지됨: ${detectedFormat || "알 수 없음"}`);
        }

        // 읽은 바이트 수를 누적하고 전체 진행률을 계산합니다.
        bytesRead += value.length;
        const progress = fileSize > 0 ? bytesRead / fileSize : 1.0;

        // `onProgress` 콜백이 제공되었다면, 진행률과 방금 읽은 청크 데이터를 전달하여 호출합니다.
        // 이 부분이 실시간 프로그레스 시각화의 핵심입니다.
        if (onProgress) {
          onProgress(progress, value);
        }
      }

      // 스트림 읽기가 모두 완료된 후, 최종 분석 결과를 생성합니다.
      logger.debug("최종 분석 결과 생성 중...");
      const extension = sfFileFormatValidator.getExtension(file.name, logger);
      const isExtensionValid = sfFileFormatValidator.isExtensionValid(
        detectedFormat,
        extension,
        logger
      );
      logger.debug(
        `확장자: '${extension}', 확장자 유효성: ${isExtensionValid}`
      );

      // 분석 결과를 상세한 객체 형태로 구성하여 반환합니다.
      if (!detectedFormat) {
        return {
          format: null,
          extension,
          isValid: false,
          reason: "지원하지 않는 파일 형식입니다.",
        };
      }
      if (!isExtensionValid) {
        return {
          format: detectedFormat,
          extension,
          isValid: false,
          reason: "파일의 실제 형식과 확장자가 일치하지 않습니다.",
        };
      }
      return { format: detectedFormat, extension, isValid: true };
    } catch (error) {
      // 분석 과정에서 오류 발생 시 로거에 기록하고 Promise를 reject하여 호출한 쪽에 에러를 알립니다.
      logger.error(`파일 스트림 분석 중 오류: ${error.message}`);
      return Promise.reject("파일을 읽는 중 오류가 발생했습니다.");
    } finally {
      // 스트림 리더의 잠금을 해제하여 리소스를 정리합니다. 이 작업은 매우 중요합니다.
      reader.releaseLock();
      logger.debug("스트림 리더 잠금 해제됨.");
    }
  }
}
