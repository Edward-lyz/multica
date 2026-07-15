import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { I18nProvider } from "@multica/core/i18n/react";
import enCommon from "@multica/views/locales/en/common.json";
import enAuth from "@multica/views/locales/en/auth.json";
import enSettings from "@multica/views/locales/en/settings.json";
import type { ReactNode } from "react";

const TEST_RESOURCES = {
  en: { common: enCommon, auth: enAuth, settings: enSettings },
};

function createWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return ({ children }: { children: ReactNode }) => (
    <I18nProvider locale="en" resources={TEST_RESOURCES}>
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    </I18nProvider>
  );
}

const {
  mockLoginWithZeroTrust,
  mockIssueCliToken,
  mockListWorkspaces,
  mockListMyInvitations,
  mockPush,
  mockReplace,
  searchParamsState,
  authStateRef,
} = vi.hoisted(() => ({
  mockLoginWithZeroTrust: vi.fn(),
  mockIssueCliToken: vi.fn(),
  mockListWorkspaces: vi.fn(),
  mockListMyInvitations: vi.fn(),
  mockPush: vi.fn(),
  mockReplace: vi.fn(),
  searchParamsState: { params: new URLSearchParams() },
  authStateRef: {
    state: {
      loginWithZeroTrust: vi.fn(),
      user: null as null | { id: string; email: string; onboarded_at?: string | null },
      isLoading: false,
    },
  },
}));

// Mock next/navigation — router spies are hoisted so tests can assert
// which navigation (if any) the page issued.
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: mockPush, replace: mockReplace }),
  usePathname: () => "/login",
  useSearchParams: () => searchParamsState.params,
}));

// Mock auth store. Keep the real
// sanitizeNextUrl so the redirect-sanitization rules are exercised rather
// than silently drifting behind a mock reimplementation.
vi.mock("@multica/core/auth", async () => {
  const actual =
    await vi.importActual<typeof import("@multica/core/auth")>(
      "@multica/core/auth",
    );
  authStateRef.state.loginWithZeroTrust = mockLoginWithZeroTrust;
  const useAuthStore = Object.assign(
    (selector: (s: typeof authStateRef.state) => unknown) =>
      selector(authStateRef.state),
    { getState: () => authStateRef.state },
  );
  return { ...actual, useAuthStore };
});

// Mock auth-cookie
vi.mock("@/features/auth/auth-cookie", () => ({
  setLoggedInCookie: vi.fn(),
}));

// Mock api
vi.mock("@multica/core/api", () => ({
  api: {
    listWorkspaces: mockListWorkspaces,
    listMyInvitations: mockListMyInvitations,
    verifyCode: vi.fn(),
    setToken: vi.fn(),
    getMe: vi.fn(),
    issueCliToken: mockIssueCliToken,
  },
}));

import LoginPage from "./page";

describe("LoginPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    searchParamsState.params = new URLSearchParams();
    authStateRef.state.user = null;
    authStateRef.state.isLoading = false;
    mockLoginWithZeroTrust.mockResolvedValue({
      id: "u1",
      email: "liyanzhen01@baidu.com",
      name: "李彦珍",
      onboarded_at: "2026-01-01T00:00:00Z",
    });
    mockListWorkspaces.mockResolvedValue([]);
    mockListMyInvitations.mockResolvedValue([]);
  });

  it("automatically authenticates through Baidu zero trust", async () => {
    render(<LoginPage />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(mockLoginWithZeroTrust).toHaveBeenCalledTimes(1);
    });
    expect(screen.getByText("百度内网登录")).toBeInTheDocument();
    expect(screen.queryByLabelText("Email")).not.toBeInTheDocument();
  });

  it("shows the authentication error and retries", async () => {
    mockLoginWithZeroTrust.mockRejectedValue(
      new Error("zero trust authentication failed"),
    );
    const user = userEvent.setup();
    render(<LoginPage />, { wrapper: createWrapper() });

    const retry = await screen.findByRole("button", { name: "重新登录" });
    expect(screen.getByText("zero trust authentication failed")).toBeInTheDocument();
    const attemptsBeforeRetry = mockLoginWithZeroTrust.mock.calls.length;
    await user.click(retry);
    await waitFor(() =>
      expect(mockLoginWithZeroTrust.mock.calls.length).toBeGreaterThan(
        attemptsBeforeRetry,
      ),
    );
  });

  it("returns a CLI token when the browser session is already authenticated", async () => {
    searchParamsState.params = new URLSearchParams({
      cli_callback: "http://localhost:58588/callback",
      cli_state: "state-123",
    });
    authStateRef.state.user = { id: "u1", email: "test@multica.ai" };
    mockIssueCliToken.mockResolvedValue({ token: "cli-jwt" });

    const hrefSetter = vi.fn();
    const originalLocation = window.location;
    Object.defineProperty(window, "location", {
      configurable: true,
      value: { ...originalLocation, set href(value: string) { hrefSetter(value); } },
    });

    try {
      render(<LoginPage />, { wrapper: createWrapper() });

      await waitFor(() => {
        expect(mockIssueCliToken).toHaveBeenCalledTimes(1);
        expect(hrefSetter).toHaveBeenCalledWith(
          "http://localhost:58588/callback?token=cli-jwt&state=state-123",
        );
      });
      expect(mockLoginWithZeroTrust).not.toHaveBeenCalled();
    } finally {
      Object.defineProperty(window, "location", {
        configurable: true,
        value: originalLocation,
      });
    }
  });

  // Regression: MUL-1080 — if the user is already authenticated on the web
  // and the Desktop app redirects them to /login?platform=desktop, the web
  // must exchange the cookie session for a bearer token and hand it off via
  // the multica:// deep link, not silently redirect to the workspace page.
  it("mints a token and deep-links to Desktop when already logged in with platform=desktop", async () => {
    searchParamsState.params = new URLSearchParams({ platform: "desktop" });
    authStateRef.state.user = { id: "u1", email: "test@multica.ai" };
    mockIssueCliToken.mockImplementation(() =>
      Promise.resolve({ token: "handoff-jwt" }),
    );

    const hrefSetter = vi.fn();
    const originalLocation = window.location;
    Object.defineProperty(window, "location", {
      configurable: true,
      value: { ...originalLocation, set href(value: string) { hrefSetter(value); } },
    });

    try {
      render(<LoginPage />, { wrapper: createWrapper() });

      await waitFor(() => {
        expect(mockIssueCliToken).toHaveBeenCalledTimes(1);
      });
      await waitFor(() => {
        expect(hrefSetter).toHaveBeenCalledWith(
          "multica://auth/callback?token=handoff-jwt",
        );
      });
      expect(
        await screen.findByRole("button", { name: "Open Multica Desktop" }),
      ).toBeInTheDocument();
    } finally {
      Object.defineProperty(window, "location", {
        configurable: true,
        value: originalLocation,
      });
    }
  });

  describe("authenticated arrival redirects", () => {
    const onboardedUser = {
      id: "u1",
      email: "test@multica.ai",
      onboarded_at: "2026-01-01T00:00:00Z",
    };

    it("fetches the workspace list before redirecting a visitor who arrived authenticated", async () => {
      // Cold Query cache on a fresh page load: reading it would say "no
      // workspaces" and misroute to /workspaces/new. The effect must fetch.
      authStateRef.state.user = onboardedUser;
      mockListWorkspaces.mockResolvedValue([{ id: "ws-1", slug: "acme" }]);

      render(<LoginPage />, { wrapper: createWrapper() });

      await waitFor(() => {
        expect(mockReplace).toHaveBeenCalledWith("/acme/issues");
      });
      expect(mockListWorkspaces).toHaveBeenCalledTimes(1);
    });

    it("still honors ?next= for a visitor who arrived authenticated", async () => {
      searchParamsState.params = new URLSearchParams({
        next: "/invite/abc",
      });
      authStateRef.state.user = onboardedUser;

      render(<LoginPage />, { wrapper: createWrapper() });

      await waitFor(() => {
        expect(mockReplace).toHaveBeenCalledWith("/invite/abc");
      });
      expect(mockListWorkspaces).not.toHaveBeenCalled();
    });
  });
});
