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
