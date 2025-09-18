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
