/**
 * sfMetadataAnalyzer.js: 메타데이터 분석 클래스
 *
 * 이 파일은 이미지 파일의 메타데이터를 분석하여 비정상적인 메타데이터를 검사하는 기능을 제공합니다.
 * exif-js 라이브러리를 사용하여 EXIF 데이터를 추출합니다.
 *
 * 지원하는 이미지 형식: JPEG, PNG, GIF, WebP, SVG
 */

class sfMetadataAnalyzer {
  /**
   * 이미지 파일의 메타데이터를 분석합니다.
   * @param {File} file 분석할 이미지 파일 (File 객체)
   * @returns {Promise<object>} 메타데이터 분석 결과를 담은 Promise
   */
  analyze(file) {
    console.log("sfMetadataAnalyzer: analyze() 호출", file); // 디버깅 로그
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        console.log("sfMetadataAnalyzer: FileReader.onload() 호출"); // 디버깅 로그
        const arrayBuffer = e.target.result;
        this.extractExifData(arrayBuffer) // EXIF 데이터 추출
          .then((exifData) => {
            console.log("sfMetadataAnalyzer: extractExifData() 성공", exifData); // 디버깅 로그
            const analysisResult = this.analyzeExifData(exifData); // EXIF 데이터 분석
            console.log(
              "sfMetadataAnalyzer: analyzeExifData() 결과",
              analysisResult
            ); // 디버깅 로그
            resolve(analysisResult); // 분석 결과를 resolve (Promise 성공)
          })
          .catch((error) => {
            console.error("sfMetadataAnalyzer: extractExifData() 실패", error); // 디버깅 로그
            reject(error); // 오류 메시지를 reject (Promise 실패)
          });
      };
      reader.onerror = (error) => {
        console.error("sfMetadataAnalyzer: FileReader.onerror() 호출", error); // 디버깅 로그
        reject(error); // 오류 메시지를 reject (Promise 실패)
      };
      reader.readAsArrayBuffer(file); // 파일을 ArrayBuffer로 읽기
    });
  }

  /**
   * ArrayBuffer에서 EXIF 데이터를 추출합니다.
   * @param {ArrayBuffer} arrayBuffer 이미지 파일의 ArrayBuffer (파일 데이터를 바이트 배열로 표현)
   * @returns {Promise<object>} EXIF 데이터를 담은 Promise
   */
  extractExifData(arrayBuffer) {
    console.log("sfMetadataAnalyzer: extractExifData() 호출", arrayBuffer); // 디버깅 로그
    return new Promise((resolve, reject) => {
      // exif-js 라이브러리를 사용하여 EXIF 데이터 추출
      EXIF.getData(arrayBuffer, function () {
        console.log(
          "sfMetadataAnalyzer: EXIF.getData() 콜백 호출",
          this.exifdata
        ); // 디버깅 로그
        if (this.exifdata) {
          // EXIF 데이터가 존재하면
          resolve(this.exifdata); // EXIF 데이터를 resolve (Promise 성공)
        } else {
          console.warn("sfMetadataAnalyzer: EXIF.getData() - EXIF 데이터 없음"); // 디버깅 로그
          resolve({}); // EXIF 데이터가 없는 경우 빈 객체를 resolve (Promise 성공)
        }
      });
      // EXIF.getData() 함수가 제대로 동작하지 않는 경우를 대비하여 timeout 설정
      setTimeout(() => {
        console.warn("sfMetadataAnalyzer: EXIF.getData() - timeout 발생"); // 디버깅 로그
        resolve({}); // timeout 발생 시 빈 객체를 resolve (Promise 성공)
      }, 5000); // 5초 timeout
    });
  }

  /**
   * EXIF 데이터를 분석하여 비정상적인 메타데이터를 검사합니다.
   * @param {object} exifData EXIF 데이터 (JavaScript 객체)
   * @returns {object} 분석 결과를 담은 객체
   */
  analyzeExifData(exifData) {
    console.log("sfMetadataAnalyzer: analyzeExifData() 호출", exifData); // 디버깅 로그
    const analysisResult = {
      hasGPSInfo: false, // GPS 정보 존재 여부
      userComment: null, // UserComment 내용
      software: null, // Software 정보
      errors: [], // 오류 메시지 배열
    };

    // GPS 정보 확인
    if (exifData.GPSLatitude && exifData.GPSLongitude) {
      analysisResult.hasGPSInfo = true; // GPS 정보가 존재하면 true로 설정
      console.log("sfMetadataAnalyzer: analyzeExifData() - GPS 정보 발견"); // 디버깅 로그
    }

    // UserComment 분석
    if (exifData.UserComment) {
      analysisResult.userComment = exifData.UserComment; // UserComment 내용 저장
      console.log(
        "sfMetadataAnalyzer: analyzeExifData() - UserComment 발견:",
        exifData.UserComment
      ); // 디버깅 로그
      if (this.isSuspiciousComment(exifData.UserComment)) {
        // UserComment가 의심스러운 내용을 포함하는지 확인
        analysisResult.errors.push(
          "UserComment에 의심스러운 내용이 포함되어 있습니다."
        ); // 오류 메시지 추가
        console.warn(
          "sfMetadataAnalyzer: analyzeExifData() - 의심스러운 UserComment 발견"
        ); // 디버깅 로그
      }
    }

    // Software 정보 분석
    if (exifData.Software) {
      analysisResult.software = exifData.Software; // Software 정보 저장
      console.log(
        "sfMetadataAnalyzer: analyzeExifData() - Software 정보 발견:",
        exifData.Software
      ); // 디버깅 로그
      if (this.isSuspiciousSoftware(exifData.Software)) {
        // Software 정보가 의심스러운지 확인
        analysisResult.errors.push("Software 정보가 의심스럽습니다."); // 오류 메시지 추가
        console.warn(
          "sfMetadataAnalyzer: analyzeExifData() - 의심스러운 Software 정보 발견"
        ); // 디버깅 로그
      }
    }

    return analysisResult; // 분석 결과 반환
  }

  /**
   * UserComment가 의심스러운 내용을 포함하는지 확인합니다.
   * @param {string} comment UserComment (문자열)
   * @returns {boolean} 의심스러운 내용이 포함되어 있으면 true, 아니면 false
   */
  isSuspiciousComment(comment) {
    console.log("sfMetadataAnalyzer: isSuspiciousComment() 호출", comment); // 디버깅 로그
    // 여기에 의심스러운 UserComment를 검사하는 로직을 추가합니다.
    // 예: 특정 키워드 포함 여부, 길이 제한 등
    const suspiciousKeywords = ["<script>", "eval(", "javascript:"]; // 의심스러운 키워드 목록
    for (const keyword of suspiciousKeywords) {
      // 키워드 목록 순회
      if (comment.toLowerCase().includes(keyword)) {
        // UserComment가 키워드를 포함하면
        console.warn(
          "sfMetadataAnalyzer: isSuspiciousComment() - 의심스러운 키워드 발견:",
          keyword
        ); // 디버깅 로그
        return true; // true 반환
      }
    }
    return false; // 의심스러운 내용이 없으면 false 반환
  }

  /**
   * Software 정보가 의심스러운지 확인합니다.
   * @param {string} software Software 정보 (문자열)
   * @returns {boolean} 의심스러우면 true, 아니면 false
   */
  isSuspiciousSoftware(software) {
    console.log("sfMetadataAnalyzer: isSuspiciousSoftware() 호출", software); // 디버깅 로그
    // 여기에 의심스러운 Software 정보를 검사하는 로직을 추가합니다.
    // 예: 특정 문자열 포함 여부, 알려지지 않은 소프트웨어 등
    const suspiciousSoftware = ["ImageMagick", "GIMP"]; // 의심스러운 Software 목록
    if (suspiciousSoftware.includes(software)) {
      // Software 정보가 목록에 포함되면
      console.warn(
        "sfMetadataAnalyzer: isSuspiciousSoftware() - 의심스러운 Software 발견:",
        software
      ); // 디버깅 로그
      return true; // true 반환
    }
    return false; // 의심스러운 내용이 없으면 false 반환
  }
}
