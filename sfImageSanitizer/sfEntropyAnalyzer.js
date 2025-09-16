/**
 * sfEntropyAnalyzer.js: 엔트로피 분석 클래스
 *
 * 이 파일은 파일의 엔트로피를 계산하여 숨겨진 데이터가 있는지 확인하는 기능을 제공합니다.
 * 엔트로피는 데이터의 무작위성을 측정하는 척도로, 높은 엔트로피는 압축되거나 암호화된 데이터가 존재할 가능성을 나타냅니다.
 *
 * 지원하는 이미지 형식: JPEG, PNG, GIF, WebP, SVG
 */

class sfEntropyAnalyzer {
  /**
   * 파일의 엔트로피를 분석합니다.
   * @param {File} file 분석할 파일 (File 객체)
   * @returns {Promise<object>} 엔트로피 분석 결과를 담은 Promise
   */
  analyze(file) {
    console.log("sfEntropyAnalyzer: analyze() 호출", file); // 디버깅 로그
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        console.log("sfEntropyAnalyzer: FileReader.onload() 호출"); // 디버깅 로그
        const arrayBuffer = e.target.result; // 파일 데이터를 ArrayBuffer로 읽기
        const uint8Array = new Uint8Array(arrayBuffer); // ArrayBuffer를 Uint8Array로 변환

        const entropy = this.calculateEntropy(uint8Array); // 엔트로피 계산
        console.log("sfEntropyAnalyzer: calculateEntropy() 결과", entropy); // 디버깅 로그
        const analysisResult = {
          entropy: entropy, // 엔트로피 값
          isSuspiciousEntropy: false, // 의심스러운 엔트로피 값 여부
          errors: [], // 오류 메시지 배열
        };

        if (this.isSuspiciousEntropy(entropy)) {
          // 엔트로피가 의심스러운지 확인
          analysisResult.isSuspiciousEntropy = true; // 의심스러운 엔트로피 값 여부 true로 설정
          analysisResult.errors.push("엔트로피가 비정상적으로 높습니다."); // 오류 메시지 추가
          console.warn(
            "sfEntropyAnalyzer: analyze() - 엔트로피가 비정상적으로 높습니다."
          ); // 디버깅 로그
        }

        resolve(analysisResult); // 분석 결과를 resolve (Promise 성공)
      };
      reader.onerror = (error) => {
        console.error("sfEntropyAnalyzer: FileReader.onerror() 호출", error); // 디버깅 로그
        reject(error); // 오류 메시지를 reject (Promise 실패)
      };
      reader.readAsArrayBuffer(file); // 파일을 ArrayBuffer로 읽기
    });
  }

  /**
   * Uint8Array의 엔트로피를 계산합니다.
   * @param {Uint8Array} uint8Array 파일 데이터 (Uint8Array 객체)
   * @returns {number} 엔트로피 값
   */
  calculateEntropy(uint8Array) {
    console.log("sfEntropyAnalyzer: calculateEntropy() 호출", uint8Array); // 디버깅 로그
    const histogram = new Array(256).fill(0); // 각 바이트 값의 빈도를 저장할 배열 (0-255)
    for (let i = 0; i < uint8Array.length; i++) {
      // 파일 데이터 순회
      histogram[uint8Array[i]]++; // 해당 바이트 값의 빈도 증가
    }

    let entropy = 0; // 엔트로피 초기화
    for (let i = 0; i < 256; i++) {
      // 각 바이트 값 순회
      const probability = histogram[i] / uint8Array.length; // 해당 바이트 값의 확률 계산
      if (probability > 0) {
        // 확률이 0보다 크면 (해당 바이트 값이 존재하면)
        entropy -= probability * Math.log2(probability); // 엔트로피 계산
      }
    }

    console.log("sfEntropyAnalyzer: calculateEntropy() - 엔트로피:", entropy); // 디버깅 로그
    return entropy; // 엔트로피 값 반환
  }

  /**
   * 엔트로피가 비정상적으로 높은지 확인합니다.
   * @param {number} entropy 엔트로피 값
   * @returns {boolean} 비정상적으로 높으면 true, 아니면 false
   */
  isSuspiciousEntropy(entropy) {
    console.log("sfEntropyAnalyzer: isSuspiciousEntropy() 호출", entropy); // 디버깅 로그
    // 여기에 비정상적인 엔트로피 값을 판단하는 로직을 추가합니다.
    // 예: 엔트로피가 특정 값 이상인지 확인
    const threshold = 7.5; // 임계값 (엔트로피가 이 값보다 크면 의심스러운 것으로 간주)
    const result = entropy > threshold; // 엔트로피가 임계값보다 크면 true 반환
    console.log("sfEntropyAnalyzer: isSuspiciousEntropy() 결과", result); // 디버깅 로그
    return result; // 엔트로피가 임계값보다 크면 true 반환
  }
}
