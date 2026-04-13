package com.medibot.healthcare_platform.modules.reportinsight.dto;

import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

@Data
public class ReportUploadRequest {
    private MultipartFile file;
}