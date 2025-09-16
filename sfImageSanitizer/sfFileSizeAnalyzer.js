/**
 * sfFileSizeAnalyzer.js: 파일 크기 분석 클래스
 *
 * 이 파일은 파일 크기를 분석하여 비정상적인 파일 크기 또는 파일 크기에 비해 이미지 크기가 너무 작은 경우를 검사하는 기능을 제공합니다.
 *
 * 지원하는 이미지 형식: JPEG, PNG, GIF, WebP, SVG
 */

class sfFileSizeAnalyzer {
  /**
   * 파일 크기를 분석합니다.
   * @param {File} file 분석할 파일 (File 객체)
   * @returns {Promise<object>} 파일 크기 분석 결과를 담은 Promise
   */
  analyze(file) {
    console.log("sfFileSizeAnalyzer: analyze() 호출", file); // 디버깅 로그
    return new Promise((resolve, reject) => {
      const analysisResult = {
        fileSize: file.size, // 파일 크기 (bytes)
        isSuspiciousSize: false, // 비정상적인 파일 크기 여부
        isSmallImageSize: false, // 파일 크기에 비해 이미지 크기가 너무 작은지 여부
        errors: [], // 오류 메시지 배열
      };

      // 비정상적인 파일 크기 확인
      if (this.isAbnormalFileSize(file.size)) {
        analysisResult.isSuspiciousSize = true; // 비정상적인 파일 크기 여부 true로 설정
        analysisResult.errors.push("파일 크기가 비정상적으로 큽니다."); // 오류 메시지 추가
        console.warn(
          "sfFileSizeAnalyzer: analyze() - 파일 크기가 비정상적으로 큽니다."
        ); // 디버깅 로그
      }

      // 파일 크기 대비 이미지 크기 확인
      this.getImageDimensions(file) // 이미지 가로, 세로 길이 가져오기
        .then((dimensions) => {
          console.log(
            "sfFileSizeAnalyzer: getImageDimensions() 성공",
            dimensions
          ); // 디버깅 로그
          if (
            this.isSmallImageSize(
              file.size,
              dimensions.width,
              dimensions.height
            )
          ) {
            // 파일 크기에 비해 이미지 크기가 너무 작은지 확인
            analysisResult.isSmallImageSize = true; // 파일 크기에 비해 이미지 크기가 너무 작은지 여부 true로 설정
            analysisResult.errors.push(
              "파일 크기에 비해 이미지 크기가 너무 작습니다."
            ); // 오류 메시지 추가
            console.warn(
              "sfFileSizeAnalyzer: analyze() - 파일 크기에 비해 이미지 크기가 너무 작습니다."
            ); // 디버깅 로그
          }
          resolve(analysisResult); // 분석 결과를 resolve (Promise 성공)
        })
        .catch((error) => {
          console.error("sfFileSizeAnalyzer: getImageDimensions() 실패", error); // 디버깅 로그
          reject(error); // 오류 메시지를 reject (Promise 실패)
        });
    });
  }

  /**
   * 파일 크기가 비정상적으로 큰지 확인합니다.
   * @param {number} fileSize 파일 크기 (bytes)
   * @returns {boolean} 비정상적으로 크면 true, 아니면 false
   */
  isAbnormalFileSize(fileSize) {
    console.log("sfFileSizeAnalyzer: isAbnormalFileSize() 호출", fileSize); // 디버깅 로그
    // 여기에 비정상적인 파일 크기를 판단하는 로직을 추가합니다.
    // 예: 파일 크기가 특정 값 이상인지 확인
    const maxFileSize = 10 * 1024 * 1024; // 10MB (최대 파일 크기)
    const result = fileSize > maxFileSize; // 파일 크기가 최대 파일 크기보다 크면 true 반환
    console.log("sfFileSizeAnalyzer: isAbnormalFileSize() 결과", result); // 디버깅 로그
    return result;
  }

  /**
   * 파일 크기에 비해 이미지 크기가 너무 작은지 확인합니다.
   * @param {number} fileSize 파일 크기 (bytes)
   * @param {number} width 이미지 너비 (pixels)
   * @param {number} height 이미지 높이 (pixels)
   * @returns {boolean} 이미지 크기가 너무 작으면 true, 아니면 false
   */
  isSmallImageSize(fileSize, width, height) {
    console.log(
      "sfFileSizeAnalyzer: isSmallImageSize() 호출",
      fileSize,
      width,
      height
    ); // 디버깅 로그
    // 여기에 이미지 크기가 너무 작은지 판단하는 로직을 추가합니다.
    // 예: 파일 크기 대비 이미지 픽셀 수가 너무 적은지 확인
    const pixelCount = width * height; // 총 픽셀 수
    const bytesPerPixel = fileSize / pixelCount; // 픽셀당 바이트 수
    const result = bytesPerPixel > 10; // 픽셀당 10 bytes 이상이면 작다고 판단 (임계값)
    console.log("sfFileSizeAnalyzer: isSmallImageSize() 결과", result); // 디버깅 로그
    return result;
  }

  /**
   * 이미지 파일의 가로, 세로 길이를 가져옵니다.
   * @param {File} file 이미지 파일 (File 객체)
   * @returns {Promise<{width: number, height: number}>} 이미지 가로, 세로 길이를 담은 Promise
   */
  getImageDimensions(file) {
    console.log("sfFileSizeAnalyzer: getImageDimensions() 호출", file); // 디버깅 로그
    return new Promise((resolve, reject) => {
      const img = new Image(); // Image 객체 생성
      img.onload = () => {
        // 이미지 로드 완료 시 이벤트 처리
        console.log(
          "sfFileSizeAnalyzer: Image.onload() 호출",
          img.width,
          img.height
        ); // 디버깅 로그
        resolve({ width: img.width, height: img.height }); // 이미지 가로, 세로 길이를 resolve (Promise 성공)
      };
      img.onerror = (error) => {
        // 이미지 로드 오류 시 이벤트 처리
        console.error("sfFileSizeAnalyzer: Image.onerror() 호출", error); // 디버깅 로그
        reject(error); // 오류 메시지를 reject (Promise 실패)
      };
      img.src = URL.createObjectURL(file); // 이미지 소스 설정 (Blob URL 생성)
    });
  }
}
