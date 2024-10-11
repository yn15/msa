package com.example.orderservice.config;

import feign.Capability;
import io.micrometer.core.instrument.MeterRegistry;

public class MicrometerCapability implements Capability {
    public MicrometerCapability(MeterRegistry registry) {
    }
}
