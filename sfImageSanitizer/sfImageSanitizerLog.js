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
