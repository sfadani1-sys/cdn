/**
 * sfJavascriptCodeAnalyzer.js: JavaScript 코드 분석 클래스
 *
 * 이 파일은 파일 내에 JavaScript 코드가 삽입되었는지 검사하는 기능을 제공합니다.
 * 이미지 파일 내에 JavaScript 코드가 존재하는 것은 비정상적인 경우이므로, 악성 코드 삽입을 의심할 수 있습니다.
 *
 * 지원하는 이미지 형식: JPEG, PNG, GIF, WebP, SVG
 */

class sfJavascriptCodeAnalyzer {
  /**
   * 파일 내 JavaScript 코드를 분석합니다.
   * @param {File} file 분석할 파일 (File 객체)
   * @returns {Promise<object>} JavaScript 코드 분석 결과를 담은 Promise
   */
  analyze(file) {
    console.log("sfJavascriptCodeAnalyzer: analyze() 호출", file); // 디버깅 로그
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        console.log("sfJavascriptCodeAnalyzer: FileReader.onload() 호출"); // 디버깅 로그
        const fileContent = e.target.result; // 파일 내용을 텍스트로 읽기
        const analysisResult = this.inspectJavascriptCode(fileContent); // JavaScript 코드 검사
        console.log(
          "sfJavascriptCodeAnalyzer: inspectJavascriptCode() 결과",
          analysisResult
        ); // 디버깅 로그
        resolve(analysisResult); // 분석 결과를 resolve (Promise 성공)
      };
      reader.onerror = (error) => {
        console.error(
          "sfJavascriptCodeAnalyzer: FileReader.onerror() 호출",
          error
        ); // 디버깅 로그
        reject(error); // 오류 메시지를 reject (Promise 실패)
      };
      reader.readAsText(file); // 파일을 텍스트 파일로 읽기
    });
  }

  /**
   * 파일 내용에서 JavaScript 코드를 검사합니다.
   * @param {string} fileContent 파일 내용 (문자열)
   * @returns {object} JavaScript 코드 분석 결과
   */
  inspectJavascriptCode(fileContent) {
    console.log(
      "sfJavascriptCodeAnalyzer: inspectJavascriptCode() 호출",
      fileContent
    ); // 디버깅 로그
    const analysisResult = {
      hasScriptTag: false, // <script> 태그 존재 여부
      hasEvalFunction: false, // eval() 함수 사용 여부
      hasFunctionConstructor: false, // Function() 생성자 사용 여부
      hasBase64Decoding: false, // Base64 디코딩 함수 (atob()) 사용 여부
      errors: [], // 오류 메시지 배열
    };

    // <script> 태그 검사
    if (fileContent.includes("<script>")) {
      analysisResult.hasScriptTag = true; // <script> 태그 존재 여부 true로 설정
      analysisResult.errors.push("<script> 태그가 발견되었습니다."); // 오류 메시지 추가
      console.warn(
        "sfJavascriptCodeAnalyzer: inspectJavascriptCode() - <script> 태그 발견"
      ); // 디버깅 로그
    }

    // eval() 함수 검사
    if (fileContent.includes("eval(")) {
      analysisResult.hasEvalFunction = true; // eval() 함수 사용 여부 true로 설정
      analysisResult.errors.push("eval() 함수가 발견되었습니다."); // 오류 메시지 추가
      console.warn(
        "sfJavascriptCodeAnalyzer: inspectJavascriptCode() - eval() 함수 발견"
      ); // 디버깅 로그
    }

    // Function() 생성자 검사
    if (fileContent.includes("Function(")) {
      analysisResult.hasFunctionConstructor = true; // Function() 생성자 사용 여부 true로 설정
      analysisResult.errors.push("Function() 생성자가 발견되었습니다."); // 오류 메시지 추가
      console.warn(
        "sfJavascriptCodeAnalyzer: inspectJavascriptCode() - Function() 생성자 발견"
      ); // 디버깅 로그
    }

    // Base64 디코딩 함수 검사
    if (fileContent.includes("atob(")) {
      analysisResult.hasBase64Decoding = true; // Base64 디코딩 함수 사용 여부 true로 설정
      analysisResult.errors.push(
        "atob() 함수 (Base64 디코딩)가 발견되었습니다."
      ); // 오류 메시지 추가
      console.warn(
        "sfJavascriptCodeAnalyzer: inspectJavascriptCode() - atob() 함수 발견"
      ); // 디버깅 로그
    }

    return analysisResult; // 분석 결과 반환
  }
}
