package com.medibot.healthcare_platform.modules.triage.service;

import com.medibot.healthcare_platform.modules.triage.client.FastApiClient;
import com.medibot.healthcare_platform.modules.triage.dto.FastApiResponse;
import com.medibot.healthcare_platform.modules.triage.dto.TriageResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class TriageService {

    private final FastApiClient fastApiClient;
    private final ChatClient.Builder chatClientBuilder;

    public TriageResponse analyzeSymptoms(List<String> symptoms) {
        // 1. Get prediction from your FastAPI model (Asynchronous call handled as block for this flow)
        FastApiResponse aiResult = fastApiClient.getPrediction(symptoms).block();

        if (aiResult == null || aiResult.getPredictions() == null || aiResult.getPredictions().isEmpty()) {
            throw new RuntimeException("AI Model could not identify symptoms: " +
                    (aiResult != null ? aiResult.getError() : "Unknown Error"));
        }

        // Get the top prediction
        FastApiResponse.PredictionData topPrediction = aiResult.getPredictions().get(0);
        String disease = topPrediction.getDisease();

        // 2. Prompt Gemini for clinical context and prevention
        String prompt = String.format(
                "The patient is likely suffering from %s. " +
                        "Provide exactly: " +
                        "1. The most relevant hospital department (e.g., Cardiology, Dermatology). " +
                        "2. Three short, actionable home prevention tips. " +
                        "3. One critical 'Red Flag' warning sign. " +
                        "Format your answer strictly as: DEPT: [Name] | TIPS: [Tip 1, Tip 2, Tip 3] | WARNING: [Text]",
                disease
        );

        String aiAdvice = chatClientBuilder.build()
                .prompt(prompt)
                .call()
                .content();

        // 3. Parse Gemini's response and build the final website response
        return buildFinalResponse(disease, topPrediction.getConfidence(), aiAdvice);
    }

    private TriageResponse buildFinalResponse(String disease, double confidence, String aiAdvice) {
        try {
            String[] parts = aiAdvice.split("\\|");
            String dept = parts[0].replace("DEPT:", "").trim();
            List<String> tips = Arrays.stream(parts[1].replace("TIPS:", "").split(","))
                    .map(String::trim)
                    .collect(Collectors.toList());
            String warning = parts[2].replace("WARNING:", "").trim();

            return TriageResponse.builder()
                    .predictedDisease(disease)
                    .confidence(confidence)
                    .recommendedDepartment(dept)
                    .