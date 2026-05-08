import "express-session";

declare module "express-session" {
  interface SessionData {
    user?: {
      id: number;
      email: string;
      mfa_enabled?: boolean;
    };

    mfa_pending?: boolean;

    mfa_user?: {
      id: number;
      email: string;
    };

    temp_mfa_secret?: string;
  }
}