import type { Request } from "express";
import type {
  ConfidentialChargeConfig,
  DetectedPayment,
} from "@cmpp/server";

/** Configuration for the stealth payment Express middleware */
export interface StealthPaymentConfig extends ConfidentialChargeConfig {
  /**
   * Optional function to determine if a request should be gated.
   * If omitted, all requests through the middleware require payment.
   */
  shouldCharge?: (req: Request) => boolean;
}

/** Extended Express Request with attached payment info */
export interface StealthPaymentRequest extends Request {
  /** Payment information attached after successful credential verification */
  payment: {
    /** The verified payment ID */
    paymentId: string;
    /** The detected on-chain payment details */
    details: DetectedPayment;
  };
}
