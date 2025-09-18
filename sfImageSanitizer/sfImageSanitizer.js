/**
 * @file sfImageSanitizer.js
 * @description 애플리케이션의 핵심 로직 컨트롤러(Controller) 클래스 파일입니다.
 */
class sfImageSanitizer {
  constructor(ui, toolbar, options = {}) {
    this.ui = ui;
    this.toolbar = toolbar;
    const logicOptions = options.logic || {};
    this.autoConvertFormat = logicOptions.autoConvertFormat ?? true;
    this.isAnalyzing = false;
    this.fileQueue = [];
    this.totalFiles = 0;
    this.processedFiles = 0;
    this.jpegCriticalMarkers = new Set(["SOI", "SOF0", "SOS", "EOI"]);
    this.logger = new sfImageSanitizerLog(logicOptions);
    this.metadataAnalyzer = new sfMetadataAnalyzer();
    this.logger.setOutput(null);

    this.analysisSteps = [
      {
        name: "파일 구조 분석",
        execute: (context) => {
          const onProgressCallback = (progress, chunkBytes) => {
            this.ui.updateProgressBar(context.file, progress);
            this.ui.updateHexPreview(context.file, chunkBytes, null);
          };
          return sfFileFormatAnalyzer.analyze(
            context.file,
            onProgressCallback,
            this.logger
          );
        },
        processResult: (result, context) => {
          context.formatResult = result;
          if (result.firstChunk)
            this.ui.updateHexPreview(
              context.file,
              result.firstChunk,
              result.magicNumber
            );
          if (result.dimensions)
            this.ui.updateResolution(
              context.file,
              result.dimensions.width,
              result.dimensions.height
            );
          if (result.structuralVerificationWarning) {
            context.hasWarnings = true;
            context.reasons.push(result.structuralVerificationWarning);
            this.logger.warning(result.structuralVerificationWarning);
          }
          if (result.isValid) {
            this.logger.info({
              key: "파일 형식",
              value: result.detectedFormat.toUpperCase(),
            });
            this.logger.success({
              key: "유효성",
              value: "파일 형식 및 확장자가 일치합니다.",
            });
          } else {
            const isMismatch =
              !result.isExtensionValid && result.detectedFormat;
            if (isMismatch && this.autoConvertFormat) {
              this.logger.warning({
                key: "자동 변환",
                value: `확장자(.${
                  result.extension
                })와 실제 형식(${result.detectedFormat.toUpperCase()})이 달라 자동 변환 후 분석을 계속합니다.`,
              });
              context.formatResult.isValid = true;
              context.correctedFileName = this._getCorrectedFileName(
                context.file.name,
                result.detectedFormat
              );
              context.hasWarnings = true;
            } else {
              context.isSafe = false;
              context.reasons.push(result.reason);
              this.logger.error({ key: "오류", value: result.reason });
            }
          }
        },
      },
      {
        name: "메타데이터 분석",
        execute: (context) =>
          this.metadataAnalyzer.analyze(
            context.file,
            context.formatResult.detectedFormat,
            this.logger
          ),
        processResult: (result, context) => {
          if (result.skipped) {
            this.logger.info(result.reason);
            return;
          }
          if (result.metadata && result.metadata.length > 0) {
            result.metadata.forEach((item) => {
              if (item.isMissing) {
                if (this.jpegCriticalMarkers.has(item.key)) {
                  this.logger.error(
                    `- [${item.key} / ${item.markerHex}] ${item.value} - 없음 (치명적 오류)`
                  );
                  context.isSafe = false;
                  context.reasons.push(
                    `${item.key} 마커가 누락되어 유효하지 않은 파일입니다.`
                  );
                } else {
                  this.logger.info(
                    `- [${item.key} / ${item.markerHex}] ${item.value} - 없음`
                  );
                }
                return;
              }
              let header = `- [${item.key}${
                item.markerHex ? ` / ${item.markerHex}` : ""
              }] ${item.value}`;
              if (item.offset !== undefined)
                header += ` (위치: ${item.offset}, 길이: ${
                  item.length || "N/A"
                } bytes)`;
              this.logger.info(header);
              if (item.details)
                this.logger.info(
                  `${item.details
                    .split("\n")
                    .map((line) => `  ${line}`)
                    .join("\n")}`
                );
              if (item.rawData && item.rawData.length > 0) {
                const dataBlockEl = document.createElement("div");
                dataBlockEl.className = "sfImageSanitizer-log-data-block";
                dataBlockEl.textContent = this._bytesToHexString(
                  item.rawData,
                  64
                );
                this.ui.addLogContent(context.file, dataBlockEl);
              }
            });
          }
          if (result.warnings && result.warnings.length > 0) {
            context.hasWarnings = true;
            context.reasons.push(...result.warnings);
            result.warnings.forEach((w) => this.logger.warning(w));
          }
          if (result.errors && result.errors.length > 0) {
            context.isSafe = false;
            context.reasons.push(...result.errors);
            result.errors.forEach((e) => this.logger.error(e));
          }
        },
      },
    ];
    this._attachEventListeners();
    this._attachToolbarListeners();
  }

  _handleLog(file, logObject) {
    this.ui.addLogMessage(file, logObject.message, logObject.level);
  }

  _attachEventListeners() {
    const { dropZoneEl, fileInputEl } = this.ui;
    if (!dropZoneEl || !fileInputEl) return;
    dropZoneEl.addEventListener(
      "click",
      () => !this.isAnalyzing && fileInputEl.click()
    );
    fileInputEl.addEventListener("change", (e) =>
      this.handleFiles(e.target.files)
    );
    dropZoneEl.addEventListener("dragenter", (e) => this._handleDrag(e, true));
    dropZoneEl.addEventListener("dragover", (e) => this._handleDrag(e));
    dropZoneEl.addEventListener("dragleave", (e) => this._handleDrag(e, false));
    dropZoneEl.addEventListener("drop", (e) => this._handleDrop(e));
  }

  _attachToolbarListeners() {
    this.toolbar.onOptionChange((key, value) => {
      if (key === "debugMode") this.logger.debugMode = value;
      if (key === "deepDebugMode") this.logger.deepDebugMode = value;
      if (key === "autoConvertFormat") this.autoConvertFormat = value;
    });
  }

  _handleDrag(e, isOver) {
    e.preventDefault();
    e.stopPropagation();
    if (typeof isOver === "boolean" && !this.isAnalyzing)
      this.ui.setDragOverState(isOver);
  }

  _handleDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    if (this.isAnalyzing) return;
    this.ui.setDragOverState(false);
    this.handleFiles(e.dataTransfer.files);
  }

  handleFiles(files) {
    if (!files || files.length === 0) return;
    if (!this.isAnalyzing) this.reset();
    this.fileQueue.push(...Array.from(files));
    this.totalFiles = this.fileQueue.length;
    this.ui.fileInputEl.value = "";
    if (!this.isAnalyzing) this.processFileQueue();
  }

  async processFileQueue() {
    this.isAnalyzing = true;
    while (this.fileQueue.length > 0) {
      const currentFile = this.fileQueue.shift();
      this.processedFiles++;
      this.ui.createResultNode(currentFile);
      const fileSizeText = `${this._formatFileSize(
        currentFile.size
      )} (${currentFile.size.toLocaleString("ko-KR")} bytes)`;
      this.ui.setupProgressViews(
        currentFile,
        currentFile.name,
        `파일 ${this.processedFiles} / ${this.totalFiles}`,
        fileSizeText
      );
      this.logger.setOutput(this._handleLog.bind(this, currentFile));

      const analysisContext = {
        file: currentFile,
        isSafe: true,
        hasWarnings: false,
        reasons: [],
        formatResult: null,
        correctedFileName: null,
      };

      for (const step of this.analysisSteps) {
        if (!analysisContext.isSafe) break;

        // [버그 수정] 'analysis'를 올바른 변수명인 'analysisContext'로 수정했습니다.
        if (
          step.name === "메타데이터 분석" &&
          !analysisContext.formatResult?.isValid
        )
          break;

        this.ui.addAnalysisStep(currentFile, step.name);
        try {
          const result = await step.execute(analysisContext);
          step.processResult(result, analysisContext);
        } catch (error) {
          analysisContext.isSafe = false;
          analysisContext.reasons.push(
            `'${step.name}' 단계에서 오류 발생: ${error.message}`
          );
          this.logger.error(
            `'${step.name}' 단계에서 예외 발생: ${error.message}`
          );
          break;
        }
      }

      this.ui.updateProgressBar(currentFile, 1.0);

      if (analysisContext.isSafe) {
        if (analysisContext.hasWarnings) {
          this.ui.showFinalResultMessage(
            currentFile,
            "분석 완료. 확인이 필요한 주의 항목이 있습니다.",
            "warning"
          );
          this.ui.setFinalState(currentFile, "warning");
        } else {
          this.ui.showFinalResultMessage(
            currentFile,
            "모든 분석 단계 통과. 안전한 파일입니다.",
            "success"
          );
          this.ui.setFinalState(currentFile, "success");
        }
        const downloadName =
          analysisContext.correctedFileName || currentFile.name;
        this.ui.showThumbnail(currentFile);
        this.ui.showDownloadButton(currentFile, downloadName);
      } else {
        this.ui.showFinalResultMessage(
          currentFile,
          "분석 실패. 잠재적 위험 요소가 발견되었습니다.",
          "error"
        );
        this.ui.setFinalState(currentFile, "error");
        this.ui.addAnalysisStep(currentFile, "상세 분석 결과");
        analysisContext.reasons.forEach((reason) => this.logger.error(reason));
      }
    }
    this.isAnalyzing = false;
  }

  _bytesToHexString(bytes, maxLength = 64) {
    if (!bytes) return "";
    const displayLength = Math.min(bytes.length, maxLength);
    let hexString = "";
    for (let i = 0; i < displayLength; i++) {
      hexString += bytes[i].toString(16).padStart(2, "0").toUpperCase() + " ";
    }
    if (bytes.length > maxLength) hexString += "...";
    return hexString.trim();
  }

  _getCorrectedFileName(originalName, newFormat) {
    const nameParts = originalName.split(".");
    nameParts.pop();
    return `${nameParts.join(".")}.${newFormat}`;
  }

  _formatFileSize(bytes) {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }

  reset() {
    this.isAnalyzing = false;
    this.fileQueue = [];
    this.totalFiles = 0;
    this.processedFiles = 0;
    this.ui.clearAllResults();
  }
}
