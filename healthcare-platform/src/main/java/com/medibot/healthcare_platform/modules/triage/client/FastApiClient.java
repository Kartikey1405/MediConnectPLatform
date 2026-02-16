////package com.medibot.healthcare_platform.modules.triage.client;
////
////import com.medibot.healthcare_platform.modules.triage.dto.SymptomRequest;
////import com.medibot.healthcare_platform.modules.triage.dto.FastApiResponse;
////import org.springframework.beans.factory.annotation.Value;
////import org.springframework.stereotype.Component;
////import org.springframework.web.reactive.function.client.WebClient;
////import reactor.core.publisher.Mono;
////
////@Component
////public class FastApiClient {
////
////    private final WebClient webClient;
////
////    public FastApiClient(WebClient.Builder builder, @Value("${ai.fastapi.url}") String baseUrl) {
////        this.webClient = builder.baseUrl(baseUrl).build();
////    }
////
////    public Mono<FastApiResponse> getPrediction(SymptomRequest request) {
////        return webClient.post()
////                .uri("/predict")
////                .bodyValue(request)
////                .retrieve()
////                .bodyToMono(FastApiResponse.class);
////    }
////}
//
//
//package com.medibot.healthcare_platform.modules.triage.client;
//
//import com.medibot.healthcare_platform.modules.triage.dto.SymptomRequest;
//import com.medibot.healthcare_platform.modules.triage.dto.FastApiResponse;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.stereotype.Component;
//import org.springframework.web.reactive.function.client.WebClient;
//import reactor.core.publisher.Mono;
//
//@Component
//public class FastApiClient {
//
//    private final WebClient webClient;
//
//    /**
//     * The @Value pulls 'ai.fastapi.url' from application.yml.
//     * Default is localhost:8000 for development.
//     */
//    public FastApiClient(WebClient.Builder builder,
//                         @Value("${ai.fastapi.url:http://localhost:8000}") String baseUrl) {
//        this.webClient = builder.baseUrl(baseUrl).build();
//    }
//
//    /**
//     * Calls your Python /predict endpoint asynchronously.
//     */
//    public Mono<FastApiResponse> getPrediction(List<String> symptoms) {
//        return webClient.post()
//                .uri("/predict")
//                .bodyValue(new SymptomRequest(symptoms))
//                .retrieve()
//                .bodyToMono(FastApiResponse.class);
//    }
//}


package com.medibot.healthcare_platform.modules.triage.client;

import com.medibot.healthcare_platform.modules.triage.dto.SymptomRequest;
import com.medibot.healthcare_platform.modules.triage.dto.FastApiResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import java.util.List;

@Component
public class FastApiClient {

    private final WebClient webClient;

    public FastApiClient(WebClient.Builder builder,
                         @Value("${ai.fastapi.url:http://localhost:8000}") String baseUrl) {
        this.webClient = builder.baseUrl(baseUrl).build();
    }

    public Mono<FastApiResponse> getPrediction(List<String> symptoms) {
        // Wrapping the list in SymptomRequest as expected by the FastAPI endpoint
        return webClient.post()
                .uri("/predict")
                .bodyValue(new SymptomRequest(symptoms))
                .retrieve()
                .bodyToMono(FastApiResponse.class);
    }
}