package io.javloom.security.auth.passwordless;

/**
 * Port for SMS dispatch — implement with Twilio, Vonage, AWS SNS, etc.
 */
public interface SmsPort {

    /**
     * Sends an SMS message to the given phone number.
     *
     * @param phone   E.164 formatted destination number
     * @param message SMS body
     */
    void send(String phone, String message);
}