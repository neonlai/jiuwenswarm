import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { resolveApiUrl } from '../../utils/env';

interface OidcStatus {
  enabled: boolean;
  required: boolean;
}

interface OidcUser {
  sub: string;
  name: string;
  preferredUsername: string;
  email: string;
}

interface OidcSession {
  authenticated?: boolean;
  user?: OidcUser;
  accessToken?: string;
  tokenType?: string;
}

function oidcUrl(path: string): string {
  return resolveApiUrl(`/api/v1/auth/oidc${path}`);
}

function rememberFederation(user: OidcUser, accessToken: string): void {
  if (!accessToken || !user.sub || typeof localStorage === 'undefined') return;
  const current = localStorage.getItem('jiuwenswarm:user_id')?.trim() || '';
  if (!current) localStorage.setItem('jiuwenswarm:user_id', user.sub);
  if ((localStorage.getItem('jiuwenswarm:user_id')?.trim() || '') !== user.sub) return;
  localStorage.setItem(
    'openjiuwen_federation',
    JSON.stringify({
      user_id: user.sub,
      token_type: 'Bearer',
      access_token: accessToken,
    }),
  );
  localStorage.setItem('openjiuwen_oidc_connection', 'oidc');
}

function clearFederation(): void {
  if (typeof localStorage === 'undefined') return;
  localStorage.removeItem('openjiuwen_federation');
  localStorage.removeItem('openjiuwen_oidc_connection');
  localStorage.removeItem('openjiuwen_oidc_renew');
}

/**
 * Icon-rail control for generic OIDC sign-in.
 * Renders nothing when the server reports OIDC is not configured, so Huawei
 * Account Kit and local use keep the previous chrome.
 */
export function OidcAccountButton() {
  const { t } = useTranslation();
  const [status, setStatus] = useState<OidcStatus | null>(null);
  const [user, setUser] = useState<OidcUser | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const statusResponse = await fetch(oidcUrl('/status'), { credentials: 'include' });
        if (!statusResponse.ok) return;
        const nextStatus = (await statusResponse.json()) as OidcStatus;
        if (cancelled || !nextStatus.enabled) {
          if (!cancelled) setStatus(nextStatus.enabled ? nextStatus : { enabled: false, required: false });
          return;
        }
        const sessionResponse = await fetch(oidcUrl('/session'), { credentials: 'include' });
        const session = sessionResponse.ok ? ((await sessionResponse.json()) as OidcSession) : null;
        if (cancelled) return;
        setStatus(nextStatus);
        if (session?.authenticated && session.user?.sub) {
          setUser(session.user);
          if (session.accessToken) rememberFederation(session.user, session.accessToken);
        } else if (nextStatus.required) {
          const returnTo = `${window.location.pathname}${window.location.search}`;
          window.location.assign(`${oidcUrl('/login')}?return_to=${encodeURIComponent(returnTo)}`);
        }
      } catch {
        // A missing route means this deployment has no OIDC login.
      }
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  if (!status?.enabled) return null;

  const signIn = () => {
    const returnTo = `${window.location.pathname}${window.location.search}`;
    window.location.assign(`${oidcUrl('/login')}?return_to=${encodeURIComponent(returnTo)}`);
  };

  const signOut = async () => {
    let endSessionUrl = '';
    try {
      const response = await fetch(oidcUrl('/logout'), { method: 'POST', credentials: 'include' });
      if (response.ok) {
        const body = (await response.json()) as { endSessionUrl?: string };
        endSessionUrl = body.endSessionUrl || '';
      }
    } catch {
      // Local sign-out still clears the browser record.
    }
    clearFederation();
    if (endSessionUrl) {
      window.location.assign(endSessionUrl);
      return;
    }
    window.location.assign('/');
  };

  const label = user ? user.name || user.preferredUsername || t('auth.oidc.account') : t('auth.oidc.signIn');
  return (
    <button
      type="button"
      className="icon-rail-nav-item"
      onClick={user ? () => void signOut() : signIn}
      data-testid="auth-oidc-account"
      data-variant={user ? 'signed-in' : 'signed-out'}
      title={label}
    >
      <span className="icon-rail-nav-item__icon" aria-hidden>
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.5">
          <circle cx="12" cy="8" r="3.25" />
          <path d="M5.5 19.25c1.4-2.7 3.7-4 6.5-4s5.1 1.3 6.5 4" strokeLinecap="round" />
        </svg>
      </span>
      <span className="icon-rail-nav-item__label">{user ? t('auth.oidc.signOut') : t('auth.oidc.signIn')}</span>
    </button>
  );
}
