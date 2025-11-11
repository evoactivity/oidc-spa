import type Transition from "@ember/routing/transition";
import Service from "@ember/service";
import { createOidc, type Oidc } from "./core";
import { tracked } from "@glimmer/tracking";

type DecodedIdTokenSchema = {
    preferred_username?: string;
    name?: string;
    email?: string;
};

export default class SessionService extends Service {
    @tracked private _decodedToken: DecodedIdTokenSchema | null = null;
    @tracked secondsLeftForAutoLogout: number | null = null;

    declare oidc: Awaited<ReturnType<typeof createOidc>>;
    declare issuerUri: string;
    declare clientId: string;
    declare scopes: string[];

    decodedIdTokenSchema = {
        parse: (data: Oidc.Tokens.DecodedIdToken_OidcCoreSpec): DecodedIdTokenSchema => {
            const parsed = data as DecodedIdTokenSchema;
            return {
                preferred_username:
                    typeof parsed.preferred_username === "string"
                        ? parsed.preferred_username
                        : undefined,
                name: typeof parsed.name === "string" ? parsed.name : undefined,
                email: typeof parsed.email === "string" ? parsed.email : undefined
            };
        }
    };

    /**
     * Initializes the OIDC service and sets up necessary subscriptions.
     */
    async setup() {
        if (this.oidc) return;
        if (!this.issuerUri || !this.clientId) {
            throw new Error("issuerUri and clientId must be set before calling setup()");
        }
        this.oidc = await createOidc({
            issuerUri: this.issuerUri,
            clientId: this.clientId,
            scopes: this.scopes,
            extraQueryParams: () => ({
                ui_locales: "en"
            }),
            decodedIdTokenSchema: this.decodedIdTokenSchema,
            debugLogs: true
        });

        if (!this.oidc.isUserLoggedIn) {
            return;
        }

        // Hook into ember's autotracking for decoded token changes
        this.oidc.subscribeToTokensChange(() => {
            if (!this.oidc.isUserLoggedIn) {
                return;
            }

            this._decodedToken = this.oidc.getDecodedIdToken() as DecodedIdTokenSchema;
        });

        // Hook into ember's autotracking for auto logout countdown
        this.oidc.subscribeToAutoLogoutCountdown(({ secondsLeft }) => {
            if ((!secondsLeft && secondsLeft !== 0) || secondsLeft > 300) {
                return;
            }

            this.secondsLeftForAutoLogout = secondsLeft;
        });
    }

    /**
     * Retrieves the decoded ID token of the authenticated user.
     */
    get decodedToken() {
        if (!this.oidc.isUserLoggedIn) {
            return null;
        }

        if (this._decodedToken) {
            return this._decodedToken;
        }

        return this.oidc.getDecodedIdToken() as DecodedIdTokenSchema;
    }

    /**
     * Indicates whether the user is currently authenticated.
     */
    get isAuthenticated() {
        return this.oidc.isUserLoggedIn;
    }

    /**
     * Retrieves the current tokens if the user is logged in.
     */
    getTokens = () => {
        if (!this.oidc.isUserLoggedIn) {
            return null;
        }

        return this.oidc.getTokens();
    };

    /**
     * Initiates the login process for the user.
     */
    login = () => {
        if (this.oidc.isUserLoggedIn) {
            return;
        }

        void this.oidc.login({ doesCurrentHrefRequiresAuth: false });
    };

    /**
     * Initiates the logout process for the user.
     */
    logout = () => {
        if (!this.oidc.isUserLoggedIn) {
            return;
        }

        void this.oidc.logout({ redirectTo: "home" });
    };

    /**
     * Initiates the registration process for the user.
     */
    register = () => {
        if (this.oidc.isUserLoggedIn) {
            return;
        }

        void this.oidc.login({
            doesCurrentHrefRequiresAuth: false,
            transformUrlBeforeRedirect: url => {
                const urlObj = new URL(url);

                urlObj.pathname = urlObj.pathname.replace(/\/auth$/, "/registrations");

                return urlObj.href;
            }
        });
    };

    /**
     * Require authentication for the current route.
     */
    requireAuthentication = (transition: Transition) => {
        if (this.oidc.isUserLoggedIn) {
            return;
        }

        transition.abort();

        void this.oidc.login({ doesCurrentHrefRequiresAuth: true });
    };

    /**
     * Prohibit access to the current route if the user is authenticated.
     */
    prohibitAuthentication = (transition: Transition, targetRoute: string) => {
        if (!this.oidc.isUserLoggedIn) {
            return;
        }

        transition.abort();
        transition.router.transitionTo(targetRoute);
    };
}
