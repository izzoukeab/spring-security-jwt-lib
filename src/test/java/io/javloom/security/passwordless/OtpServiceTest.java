package io.javloom.security.auth.passwordless;

import io.javloom.commons.exception.ApiException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OtpServiceTest {

    @Mock private OtpStore otpStore;
    @Mock private SmsPort  smsPort;

    private OtpService otpService;

    @BeforeEach
    void setup() {
        otpService = new OtpService(otpStore, smsPort);
    }

    @Test
    void should_generate_and_send_otp() {
        otpService.sendOtp("+33612345678");

        verify(otpStore).save(eq("+33612345678"), any(String.class), any(Duration.class));
        verify(smsPort).send(eq("+33612345678"), any(String.class));
    }

    @Test
    void should_verify_valid_otp() {
        when(otpStore.find("+33612345678")).thenReturn(Optional.of("123456"));

        assertThatNoException().isThrownBy(() ->
                otpService.verifyOtp("+33612345678", "123456"));

        verify(otpStore).delete("+33612345678");
    }

    @Test
    void should_throw_when_otp_not_found() {
        when(otpStore.find("+33612345678")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> otpService.verifyOtp("+33612345678", "123456"))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("expired or not found");
    }

    @Test
    void should_throw_when_otp_is_invalid() {
        when(otpStore.find("+33612345678")).thenReturn(Optional.of("123456"));

        assertThatThrownBy(() -> otpService.verifyOtp("+33612345678", "999999"))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("Invalid OTP");
    }

    @Test
    void should_not_delete_otp_on_failed_verification() {
        when(otpStore.find("+33612345678")).thenReturn(Optional.of("123456"));

        assertThatThrownBy(() -> otpService.verifyOtp("+33612345678", "000000"))
                .isInstanceOf(ApiException.class);
    }
}