/**
 * sfSpecificStringAnalyzer.js: 특정 문자열 분석 클래스
 *
 * 이 파일은 파일 내에 악성 코드와 관련된 특정 문자열이 있는지 검사하는 기능을 제공합니다.
 * 이러한 문자열은 웹 쉘, 코드 실행 함수, 난독화 등에 사용될 수 있으므로, 악성 코드 삽입을 의심할 수 있습니다.
 *
 * 지원하는 이미지 형식: JPEG, PNG, GIF, WebP, SVG
 */

class sfSpecificStringAnalyzer {
  /**
   * 파일 내 특정 문자열을 분석합니다.
   * @param {File} file 분석할 파일 (File 객체)
   * @returns {Promise<object>} 특정 문자열 분석 결과를 담은 Promise
   */
  analyze(file) {
    console.log("sfSpecificStringAnalyzer: analyze() 호출", file); // 디버깅 로그
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        console.log("sfSpecificStringAnalyzer: FileReader.onload() 호출"); // 디버깅 로그
        const fileContent = e.target.result; // 파일 내용을 텍스트로 읽기
        const analysisResult = this.inspectSpecificStrings(fileContent); // 특정 문자열 검사
        console.log(
          "sfSpecificStringAnalyzer: inspectSpecificStrings() 결과",
          analysisResult
        ); // 디버깅 로그
        resolve(analysisResult); // 분석 결과를 resolve (Promise 성공)
      };
      reader.onerror = (error) => {
        console.error(
          "sfSpecificStringAnalyzer: FileReader.onerror() 호출",
          error
        ); // 디버깅 로그
        reject(error); // 오류 메시지를 reject (Promise 실패)
      };
      reader.readAsText(file); // 파일을 텍스트 파일로 읽기
    });
  }

  /**
   * 파일 내용에서 특정 문자열을 검사합니다.
   * @param {string} fileContent 파일 내용 (문자열)
   * @returns {object} 특정 문자열 분석 결과
   */
  inspectSpecificStrings(fileContent) {
    console.log(
      "sfSpecificStringAnalyzer: inspectSpecificStrings() 호출",
      fileContent
    ); // 디버깅 로그
    const analysisResult = {
      hasSuspiciousString: false, // 의심스러운 문자열 존재 여부
      errors: [], // 오류 메시지 배열
    };

    const suspiciousStrings = [
      "<?php", // PHP 코드 시작 태그
      "<%", // ASP 코드 시작 태그
      "shell_exec", // 쉘 명령어 실행 함수 (PHP)
      "system(", // 시스템 명령어 실행 함수 (PHP)
      "passthru(", // 시스템 명령어 실행 함수 (PHP)
      "exec(", // 시스템 명령어 실행 함수 (PHP)
      "base64_decode(", // Base64 디코딩 함수 (PHP)
      "chr(", // 문자 코드 변환 함수 (PHP)
      "String.fromCharCode(", // 문자 코드 변환 함수 (JavaScript)
    ];

    for (const str of suspiciousStrings) {
      // 의심스러운 문자열 목록 순회
      if (fileContent.includes(str)) {
        // 파일 내용에 해당 문자열이 포함되어 있으면
        analysisResult.hasSuspiciousString = true; // 의심스러운 문자열 존재 여부 true로 설정
        analysisResult.errors.push(
          `의심스러운 문자열 "${str}"이(가) 발견되었습니다.`
        ); // 오류 메시지 추가
        console.warn(
          "sfSpecificStringAnalyzer: inspectSpecificStrings() - 의심스러운 문자열 발견:",
          str
        ); // 디버깅 로그
      }
    }

    return analysisResult; // 분석 결과 반환
  }
}
