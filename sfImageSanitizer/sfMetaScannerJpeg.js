/**
 * @file sfMetaScannerJpeg.js
 * @description [완전 독립화] JPEG 파일의 모든 것을 분석하는 완전한 전문 스캐너.
 *
 * 이 클래스는 이제 마커 스캔, 내용 파싱, EXIF 태그 분석 등 JPEG와 관련된
 * 모든 분석을 책임지는 완전 독립적인 모듈입니다.
 * @dependency exif.min.js (이 기능을 사용하기 위해 HTML에 반드시 로드되어야 함)
 */
class sfMetaScannerJpeg {
  static JPEG_MARKERS = {
    0xffc0: { abbr: "SOF0", name: "Start of Frame 0: Baseline DCT" },
    0xffc1: { abbr: "SOF1", name: "Start of Frame 1: Extended sequential DCT" },
    0xffc2: { abbr: "SOF2", name: "Start of Frame 2: Progressive DCT" },
    0xffc3: { abbr: "SOF3", name: "Start of Frame 3: Lossless (sequential)" },
    0xffc4: { abbr: "DHT", name: "Define Huffman Table(s)" },
    0xffc5: {
      abbr: "SOF5",
      name: "Start of Frame 5: Differential sequential DCT",
    },
    0xffc6: {
      abbr: "SOF6",
      name: "Start of Frame 6: Differential progressive DCT",
    },
    0xffc7: { abbr: "SOF7", name: "Start of Frame 7: Differential lossless" },
    0xffc8: { abbr: "JPG", name: "Reserved for JPEG extensions" },
    0xffc9: {
      abbr: "SOF9",
      name: "Start of Frame 9: Extended sequential DCT, arithmetic coding",
    },
    0xffca: {
      abbr: "SOF10",
      name: "Start of Frame 10: Progressive DCT, arithmetic coding",
    },
    0xffcb: {
      abbr: "SOF11",
      name: "Start of Frame 11: Lossless (sequential), arithmetic coding",
    },
    0xffcc: { abbr: "DAC", name: "Define Arithmetic Coding Conditioning(s)" },
    0xffcd: {
      abbr: "SOF13",
      name: "Start of Frame 13: Differential sequential DCT, arithmetic coding",
    },
    0xffce: {
      abbr: "SOF14",
      name: "Start of Frame 14: Differential progressive DCT, arithmetic coding",
    },
    0xffcf: {
      abbr: "SOF15",
      name: "Start of Frame 15: Differential lossless, arithmetic coding",
    },
    0xffd0: { abbr: "RST0", name: "Restart with modulo 8 count 0" },
    0xffd1: { abbr: "RST1", name: "Restart with modulo 8 count 1" },
    0xffd2: { abbr: "RST2", name: "Restart with modulo 8 count 2" },
    0xffd3: { abbr: "RST3", name: "Restart with modulo 8 count 3" },
    0xffd4: { abbr: "RST4", name: "Restart with modulo 8 count 4" },
    0xffd5: { abbr: "RST5", name: "Restart with modulo 8 count 5" },
    0xffd6: { abbr: "RST6", name: "Restart with modulo 8 count 6" },
    0xffd7: { abbr: "RST7", name: "Restart with modulo 8 count 7" },
    0xffd8: { abbr: "SOI", name: "Start of Image" },
    0xffd9: { abbr: "EOI", name: "End of Image" },
    0xffda: { abbr: "SOS", name: "Start of Scan" },
    0xffdb: { abbr: "DQT", name: "Define Quantization Table(s)" },
    0xffdc: { abbr: "DNL", name: "Define Number of Lines" },
    0xffdd: { abbr: "DRI", name: "Define Restart Interval" },
    0xffde: { abbr: "DHP", name: "Define Hierarchical Progression" },
    0xffdf: { abbr: "EXP", name: "Expand Reference Component(s)" },
    0xffe0: { abbr: "APP0", name: "Application Segment 0 (JFIF, JFXX)" },
    0xffe1: { abbr: "APP1", name: "Application Segment 1 (EXIF, XMP)" },
    0xffe2: {
      abbr: "APP2",
      name: "Application Segment 2 (ICC Profile, FlashPix)",
    },
    0xffe3: { abbr: "APP3", name: "Application Segment 3" },
    0xffe4: { abbr: "APP4", name: "Application Segment 4" },
    0xffe5: { abbr: "APP5", name: "Application Segment 5" },
    0xffe6: { abbr: "APP6", name: "Application Segment 6" },
    0xffe7: { abbr: "APP7", name: "Application Segment 7" },
    0xffe8: { abbr: "APP8", name: "Application Segment 8" },
    0xffe9: { abbr: "APP9", name: "Application Segment 9" },
    0xffea: { abbr: "APP10", name: "Application Segment 10" },
    0xffeb: { abbr: "APP11", name: "Application Segment 11" },
    0xffec: { abbr: "APP12", name: "Application Segment 12 (Picture Info)" },
    0xffed: { abbr: "APP13", name: "Application Segment 13 (Photoshop IRB)" },
    0xffee: { abbr: "APP14", name: "Application Segment 14 (Adobe)" },
    0xffef: { abbr: "APP15", name: "Application Segment 15" },
    0xfff0: { abbr: "JPG0", name: "Reserved for JPEG extensions" },
    0xfffd: { abbr: "JPG13", name: "Reserved for JPEG extensions" },
    0xfffe: { abbr: "COM", name: "Comment" },
    0xff01: { abbr: "TEM", name: "Temporary private use in arithmetic coding" },
  };

  static STANDALONE_MARKERS = new Set([
    0xffd8, 0xffd9, 0xff01, 0xffd0, 0xffd1, 0xffd2, 0xffd3, 0xffd4, 0xffd5,
    0xffd6, 0xffd7,
  ]);
  static CRITICAL_MARKERS = new Set(["SOI", "SOF0", "SOS", "EOI"]);
  static COMMON_MARKERS = new Set(["DQT", "DHT", "APP0"]);

  static async scan(file, logger) {
    const bytes = await this._readFileAsBytes(file);
    if (!bytes) {
      return {
        errors: ["파일을 읽는 중 오류 발생"],
        metadata: [],
        skipped: false,
      };
    }
    const view = new DataView(bytes.buffer);

    const markerResult = this._scanAllMarkers(bytes, view, logger);
    const exifResult = await this._analyzeJPEG_EXIF(bytes.buffer, logger);

    if (exifResult.metadata.length > 0) {
      const app1Item = markerResult.metadata.find(
        (item) => item.key === "APP1"
      );
      if (app1Item) {
        const exifDetails = exifResult.metadata
          .map((meta) => `    - ${meta.key}: ${meta.value}`)
          .join("\n");
        app1Item.details =
          (app1Item.details ? app1Item.details + "\n" : "") + exifDetails;
      }
    }

    return {
      errors: [...markerResult.errors, ...(exifResult.errors || [])],
      warnings: [...markerResult.warnings, ...(exifResult.warnings || [])],
      metadata: markerResult.metadata,
      skipped: false,
    };
  }

  static _readFileAsBytes(file) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => resolve(new Uint8Array(e.target.result));
      reader.onerror = () => resolve(null);
      reader.readAsArrayBuffer(file);
    });
  }

  static _scanAllMarkers(bytes, view, logger) {
    if (logger) logger.trace("[JPEG 멀티-패스 스캔] 시작...");
    let allMetadata = [];
    const allFoundKeys = new Set();
    const errors = [];

    if (logger) logger.trace(" -> 1차 스캔 (메인 이미지) 시작...");
    const mainImageScan = this._scanSegment(bytes, view, 0, logger);
    allMetadata.push(...mainImageScan.metadata);
    mainImageScan.foundKeys.forEach((key) => allFoundKeys.add(key));

    let firstEoiIndex = -1;
    for (let i = mainImageScan.endOfScanIndex || 0; i < bytes.length - 1; i++) {
      if (bytes[i] === 0xff && bytes[i + 1] === 0xd9) {
        firstEoiIndex = i;
        break;
      }
    }

    if (firstEoiIndex !== -1) {
      allMetadata.push({
        key: "EOI",
        value: "End of Image",
        offset: firstEoiIndex,
        markerHex: "0xFFD9",
        length: 2,
      });
      allFoundKeys.add("EOI");
      const trailingDataIndex = firstEoiIndex + 2;
      if (trailingDataIndex < bytes.length) {
        if (logger)
          logger.trace(
            ` -> EOI 이후 후행 데이터 발견. 2차 스캔 시작 at offset=${trailingDataIndex}...`
          );
        allMetadata.push({
          key: "TRAILING_DATA",
          value: "--- 후행 데이터 시작 ---",
          offset: trailingDataIndex,
        });
        if (view.getUint16(trailingDataIndex, false) === 0xffed) {
          allMetadata.push({
            key: "INFO",
            value:
              "후행 데이터는 Photoshop 메타데이터(IRB)일 가능성이 높습니다.",
          });
        }
        const trailingScan = this._scanSegment(
          bytes,
          view,
          trailingDataIndex,
          logger
        );
        allMetadata.push(...trailingScan.metadata);
        trailingScan.foundKeys.forEach((key) => allFoundKeys.add(key));
      }
    }

    const allEssential = [...this.CRITICAL_MARKERS, ...this.COMMON_MARKERS];
    allEssential.forEach((key) => {
      if (!allFoundKeys.has(key)) {
        let markerInfo,
          markerCodeHex = "N/A";
        for (const code in this.JPEG_MARKERS) {
          if (this.JPEG_MARKERS[code].abbr === key) {
            markerInfo = this.JPEG_MARKERS[code];
            markerCodeHex = `0x${parseInt(code).toString(16).toUpperCase()}`;
            break;
          }
        }
        allMetadata.push({
          key,
          value: markerInfo.name,
          markerHex: markerCodeHex,
          isMissing: true,
        });
      }
    });

    allMetadata.sort((a, b) =>
      a.isMissing
        ? 1
        : b.isMissing
        ? -1
        : (a.offset || Infinity) - (b.offset || Infinity)
    );

    return { errors, metadata: allMetadata, warnings: [] };
  }

  static _scanSegment(bytes, view, startIndex, logger) {
    let i = startIndex;
    const metadata = [];
    const foundKeys = new Set();
    while (i < bytes.length - 1) {
      if (bytes[i] !== 0xff) {
        i++;
        continue;
      }
      const markerSecondByte = bytes[i + 1];
      if (markerSecondByte === 0x00 || markerSecondByte === 0xff) {
        i++;
        continue;
      }
      const markerCode = view.getUint16(i, false);
      const markerInfo = this.JPEG_MARKERS[markerCode];
      const markerHex = `0x${markerCode.toString(16).toUpperCase()}`;
      let newMetaItem = null;
      if (markerInfo) {
        newMetaItem = {
          key: markerInfo.abbr,
          value: markerInfo.name,
          offset: i,
          markerHex,
        };
        foundKeys.add(markerInfo.abbr);
      } else if (markerCode >= 0xff02 && markerCode <= 0xffbf) {
        newMetaItem = {
          key: `RES(${markerHex})`,
          value: "Reserved Marker",
          offset: i,
          markerHex,
        };
      }
      if (newMetaItem) {
        if (this.STANDALONE_MARKERS.has(markerCode)) {
          newMetaItem.length = 2;
          i += 2;
        } else {
          if (i + 4 > bytes.length) {
            metadata.push(newMetaItem);
            break;
          }
          const segmentLength = view.getUint16(i + 2, false);
          newMetaItem.length = segmentLength + 2;
          const dataOffset = i + 4;
          const dataLength = segmentLength - 2;
          if (dataOffset + dataLength <= bytes.length) {
            const dataSegment = bytes.slice(
              dataOffset,
              dataOffset + dataLength
            );
            newMetaItem.rawData = dataSegment;
            newMetaItem.details = null;
            switch (markerCode) {
              case 0xffe0:
                newMetaItem.details = this._parseAPP0(dataSegment);
                break;
              case 0xffe1:
                newMetaItem.details = this._parseAPP1(dataSegment);
                break;
              case 0xffdb:
                newMetaItem.details = this._parseDQT(dataSegment);
                break;
              case 0xffc0:
                newMetaItem.details = this._parseSOF0(dataSegment);
                break;
              case 0xffc4:
                newMetaItem.details = this._parseDHT(dataSegment);
                break;
              case 0xffda:
                newMetaItem.details = this._parseSOS(dataSegment);
                break;
              case 0xfffe:
                newMetaItem.details = this._parseCOM(dataSegment);
                break;
            }
          }
          if (markerCode === 0xffda) {
            metadata.push(newMetaItem);
            return {
              metadata,
              foundKeys,
              endOfScanIndex: i + segmentLength + 2,
            };
          }
          i += segmentLength + 2;
        }
        metadata.push(newMetaItem);
      } else {
        i += 2;
      }
    }
    return { metadata, foundKeys, endOfScanIndex: i };
  }

  static _parseAPP0(segmentBytes) {
    const identifier = new TextDecoder().decode(segmentBytes.slice(0, 5));
    if (identifier === "JFIF\0") {
      const major = segmentBytes[5],
        minor = segmentBytes[6],
        units = segmentBytes[7];
      const xDensity = (segmentBytes[8] << 8) | segmentBytes[9],
        yDensity = (segmentBytes[10] << 8) | segmentBytes[11];
      return `식별자: JFIF\n    버전: ${major}.${String(minor).padStart(
        2,
        "0"
      )}\n    밀도 단위: ${
        units === 0 ? "종횡비" : units === 1 ? "인치당 픽셀" : "cm당 픽셀"
      }\n    밀도: ${xDensity}x${yDensity}`;
    }
    return "Non-JFIF APP0 segment";
  }

  static _parseAPP1(segmentBytes) {
    if (segmentBytes.length < 6) return "Invalid APP1 segment";
    const identifier = new TextDecoder().decode(segmentBytes.slice(0, 6));
    if (identifier === "Exif\0\0") {
      const tiffHeaderOffset = 6;
      if (segmentBytes.length < tiffHeaderOffset + 8)
        return "Incomplete EXIF data (missing TIFF header)";
      const view = new DataView(segmentBytes.buffer, segmentBytes.byteOffset);
      const byteOrderMarker = view.getUint16(tiffHeaderOffset, false);
      const isLittleEndian = byteOrderMarker === 0x4949,
        isBigEndian = byteOrderMarker === 0x4d4d;
      let report = `식별자: Exif (${this._bytesToHexString(
        segmentBytes.slice(0, 6)
      )})\n`;
      if (isLittleEndian || isBigEndian) {
        report += `    TIFF 헤더: ${this._bytesToHexString(
          segmentBytes.slice(tiffHeaderOffset, tiffHeaderOffset + 4)
        )} (${isLittleEndian ? "Little Endian" : "Big Endian"})`;
      } else {
        report += `    TIFF 헤더: 알 수 없음`;
      }
      return report;
    }
    if (
      new TextDecoder().decode(segmentBytes.slice(0, 29)) ===
      "http://ns.adobe.com/xap/1.0/\0"
    ) {
      return `식별자: XMP (Adobe Extensible Metadata Platform)`;
    }
    return "알 수 없는 APP1 데이터";
  }

  static _parseSOF0(segmentBytes) {
    if (segmentBytes.length < 6) return "Invalid SOF0 segment";
    const view = new DataView(
      segmentBytes.buffer,
      segmentBytes.byteOffset,
      segmentBytes.byteLength
    );
    const precision = view.getUint8(0),
      height = view.getUint16(1, false),
      width = view.getUint16(3, false),
      components = view.getUint8(5);
    return `정밀도: ${precision}-bit\n    이미지 크기: ${width}x${height}\n    구성요소 수: ${components}`;
  }

  static _parseDQT(segmentBytes) {
    const precision = segmentBytes[0] >> 4 === 0 ? "8-bit" : "16-bit",
      tableId = segmentBytes[0] & 0x0f;
    return `정밀도: ${precision}, 테이블 ID: ${tableId}`;
  }

  static _parseDHT(segmentBytes) {
    const classAndId = segmentBytes[0],
      tableClass = classAndId >> 4 === 0 ? "DC" : "AC",
      tableId = classAndId & 0x0f;
    return `클래스: ${tableClass}, 테이블 ID: ${tableId}`;
  }

  static _parseSOS(segmentBytes) {
    return `구성요소 수: ${segmentBytes[0]}`;
  }

  static _parseCOM(segmentBytes) {
    try {
      const comment = new TextDecoder().decode(segmentBytes);
      return comment.length > 70 ? comment.substring(0, 70) + "..." : comment;
    } catch (e) {
      return "Invalid comment encoding";
    }
  }

  static _bytesToHexString(bytes) {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0").toUpperCase())
      .join(" ");
  }

  static _analyzeJPEG_EXIF(arrayBuffer, logger) {
    return new Promise(async (resolve) => {
      const exifData = await this.extractExifData(arrayBuffer);
      resolve(this.analyzeExifData(exifData));
    });
  }

  static extractExifData(arrayBuffer) {
    return new Promise((resolve) => {
      let resolved = false;
      const timeoutId = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          resolve({});
        }
      }, 2000);
      try {
        window.EXIF.getData(arrayBuffer, function () {
          if (!resolved) {
            clearTimeout(timeoutId);
            resolved = true;
            resolve(this.exifdata || {});
          }
        });
      } catch (error) {
        if (!resolved) {
          clearTimeout(timeoutId);
          resolved = true;
          resolve({});
        }
      }
    });
  }

  static analyzeExifData(exifData) {
    const result = { warnings: [], metadata: [] };
    if (exifData.GPSLatitude && exifData.GPSLongitude) {
      result.warnings.push("개인정보 주의: GPS 위치 정보가 포함되어 있습니다.");
      result.metadata.push({
        key: "GPS Latitude",
        value: exifData.GPSLatitude.join(", "),
      });
      result.metadata.push({
        key: "GPS Longitude",
        value: exifData.GPSLongitude.join(", "),
      });
    }
    if (exifData.UserComment) {
      result.metadata.push({
        key: "UserComment",
        value: String(exifData.UserComment),
      });
      if (this.isSuspiciousComment(String(exifData.UserComment))) {
        result.warnings.push(
          "보안 주의: UserComment에 의심스러운 내용(스크립트 등)이 포함될 수 있습니다."
        );
      }
    }
    if (exifData.Software) {
      result.metadata.push({ key: "Software", value: exifData.Software });
    }
    return result;
  }

  static isSuspiciousComment(comment) {
    return ["<script>", "eval(", "javascript:"].some((k) =>
      comment.toLowerCase().includes(k)
    );
  }
}
