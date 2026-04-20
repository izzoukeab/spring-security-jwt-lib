package io.javloom.security.auth.passwordless;

import io.javloom.security.exception.JwtSecurityException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;

/**
 * Manages OTP lifecycle — generation, dispatch, and verification.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OtpService {

    private static final int OTP_LENGTH = 6;
    private static final Duration OTP_TTL = Duration.ofMinutes(5);
    private static final String SMS_TEMPLATE = "Your verification code is: %s. Valid for 5 minutes.";

    private static final SecureRandom RANDOM = new SecureRandom();

    private final OtpStore otpStore;
    private final SmsPort smsPort;

    /**
     * Generates a 6-digit OTP, stores it, and sends it via SMS.
     *
     * @param phone E.164 phone number
     */
    public void sendOtp(final String phone) {
        String code = generateCode();
        otpStore.save(phone, code, OTP_TTL);
        smsPort.send(phone, String.format(SMS_TEMPLATE, code));
        log.debug("OTP sent to phone: {}", maskPhone(phone));
    }

    /**
     * Verifies the OTP code for the given phone number.
     * Deletes the code on successful verification — one-time use enforced.
     *
     * @param phone E.164 phone number
     * @param code  submitted OTP code
     * @throws JwtSecurityException if the code is invalid or expired
     */
    public void verifyOtp(final String phone, final String code) {
        String stored = otpStore.find(phone)
                .orElseThrow(() -> JwtSecurityException.unauthorized("OTP expired or not found"));

        if (!stored.equals(code)) {
            log.warn("Invalid OTP attempt for phone: {}", maskPhone(phone));
            throw JwtSecurityException.unauthorized("Invalid OTP code");
        }

        otpStore.delete(phone);
        log.debug("OTP verified successfully for phone: {}", maskPhone(phone));
    }

    /**
     * Generates a zero-padded numeric OTP of {@value #OTP_LENGTH} digits.
     *
     * @return OTP string
     */
    private String generateCode() {
        int bound = (int) Math.pow(10, OTP_LENGTH);
        return String.format("%0" + OTP_LENGTH + "d", RANDOM.nextInt(bound));
    }

    /**
     * Masks a phone number for safe logging — shows only last 4 digits.
     *
     * @param phone E.164 phone number
     * @return masked phone string
     */
    private String maskPhone(final String phone) {
        if (phone == null || phone.length() < 4) return "****";
        return "*".repeat(phone.length() - 4) + phone.substring(phone.length() - 4);
    }
}