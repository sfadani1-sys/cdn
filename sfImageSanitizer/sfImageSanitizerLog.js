// 파일이름: sfImageSanitizerLog.js

/**
 * @file sfImageSanitizerLog.js
 * @description 중앙 집중식 로깅 클래스 파일입니다.
 *
 * 이 클래스는 애플리케이션 전체의 로그 메시지를 관리하고, 설정된 출력(UI)으로 전달합니다.
 * 디버그 모드를 지원하여, 개발 중에만 상세한 내부 동작 로그를 볼 수 있도록 제어합니다.
 * 이 클래스는 인스턴스화되어 사용됩니다 (예: new sfImageSanitizerLog(options)).
 */
class sfImageSanitizerLog {
  /**
   * 로거 생성자입니다.
   * @param {object} [options={}] - 로거 설정을 위한 옵션 객체.
   * @param {boolean} [options.debugMode=false] - 디버그 모드를 활성화할지 여부.
   */
  constructor(options = {}) {
    /**
     * @property {boolean} debugMode - 디버그 모드 활성화 여부. true일 경우 debug 수준의 로그가 출력됩니다.
     */
    // 옵션에서 debugMode 값을 가져옵니다. 값이 없으면(undefined 또는 null) 기본값으로 false를 사용합니다.
    this.debugMode = options.debugMode ?? false;

    /**
     * @property {?function} outputCallback - 로그 메시지를 실제로 출력할 외부 함수(콜백).
     *                                       초기에는 아무것도 연결되어 있지 않으므로 null로 설정합니다.
     */
    this.outputCallback = null;
  }

  /**
   * 로그 메시지를 전달받을 콜백 함수를 등록(연결)합니다.
   * `sfImageSanitizer.js`에서 이 메서드를 사용하여 UI의 로깅 함수를 연결합니다.
   * @param {function} callback - 로그 객체({level, message, timestamp})를 인자로 받는 콜백 함수.
   */
  setOutput(callback) {
    this.outputCallback = callback;
  }

  /**
   * 정보(Information) 수준의 로그를 기록합니다. 이 로그는 사용자가 알아야 할 일반적인 진행 상황을 나타내며, 항상 출력됩니다.
   * @param {string} message - 기록할 로그 메시지.
   */
  info(message) {
    this._log("info", message);
  }

  /**
   * 성공(Success) 수준의 로그를 기록합니다. 작업이 성공적으로 완료되었음을 나타내며, 항상 출력됩니다.
   * @param {string} message - 기록할 로그 메시지.
   */
  success(message) {
    this._log("success", message);
  }

  /**
   * 오류(Error) 수준의 로그를 기록합니다. 예기치 않은 문제나 실패가 발생했음을 나타내며, 항상 출력됩니다.
   * @param {string} message - 기록할 로그 메시지.
   */
  error(message) {
    this._log("error", message);
  }

  /**
   * 디버그(Debug) 수준의 로그를 기록합니다.
   * 이 로그는 생성자에서 전달받은 `debugMode`가 true일 때만 출력됩니다.
   * 주로 함수 호출, 변수 값 추적 등 개발자에게만 유용한 상세 정보를 기록하는 데 사용됩니다.
   * @param {string} message - 기록할 로그 메시지.
   */
  debug(message) {
    if (this.debugMode) {
      this._log("debug", message);
    }
  }

  /**
   * 로그 객체를 생성하고, 등록된 출력 콜백으로 전달하는 내부(private) 메서드입니다.
   * 모든 공개 로깅 메서드(info, success 등)가 이 메서드를 호출하여 코드 중복을 피합니다.
   * @private
   * @param {'info'|'success'|'error'|'debug'} level - 로그 수준.
   * @param {string} message - 로그 메시지.
   */
  _log(level, message) {
    // 로그 정보를 담을 표준 객체를 생성합니다.
    const logObject = {
      level: level, // 로그의 종류 (UI에서는 CSS 클래스로, 콘솔에서는 출력 메서드 선택에 사용됨)
      message: message, // 실제 로그 내용
      timestamp: new Date(), // 로그가 발생한 정확한 시간
    };

    // `outputCallback`이 등록되어 있다면(즉, `setOutput`이 호출되었다면),
    // 생성된 로그 객체를 전달하여 호출합니다. 이 부분이 UI와 연결되는 핵심 지점입니다.
    if (this.outputCallback) {
      this.outputCallback(logObject);
    }

    // 개발자의 편의를 위해 브라우저의 개발자 도구 콘솔에도 로그를 출력합니다.
    // 로그 수준에 따라 적절한 console 메서드를 사용하여, 콘솔의 필터링 기능을 활용할 수 있습니다.
    switch (level) {
      case "success":
      case "info":
        // `console.info`는 정보성 로그를 나타내며, 보통 앞에 'i' 아이콘이 붙습니다.
        console.info(`[${level.toUpperCase()}] ${message}`);
        break;
      case "error":
        // `console.error`는 오류 로그를 나타내며, 보통 빨간색으로 강조되고 스택 트레이스를 포함할 수 있습니다.
        console.error(`[ERROR] ${message}`);
        break;
      case "debug":
        // 디버그 로그는 다른 색상으로 표시하여 일반 로그와 시각적으로 구분합니다.
        // `%c` 지시자는 뒤따르는 문자열에 CSS 스타일을 적용하도록 합니다.
        console.log(`%c[DEBUG] ${message}`, "color: #999; font-style: italic;");
        break;
    }
  }
}
