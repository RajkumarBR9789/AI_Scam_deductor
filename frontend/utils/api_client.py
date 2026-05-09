"""
HTTP API client for the ScamShield Streamlit frontend.

All methods return a structured dict:
    {"success": bool, "data": dict | None, "error": str | None}

Handles timeouts, connection errors, and non-2xx HTTP responses gracefully.
Includes automatic token refresh on 401 responses.
"""

import os
from typing import Any

import requests
import streamlit as st

_DEFAULT_BASE_URL = "http://localhost:8000"
_TIMEOUT_SECONDS = 5


class APIClient:
    """Thin wrapper around requests for ScamShield backend calls."""

    def __init__(self, base_url: str | None = None) -> None:
        self._base_url = (
            base_url
            or os.getenv("STREAMLIT_API_BASE_URL", _DEFAULT_BASE_URL)
        ).rstrip("/")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ok(self, data: Any) -> dict:
        return {"success": True, "data": data, "error": None}

    def _err(self, message: str) -> dict:
        return {"success": False, "data": None, "error": message}

    def _try_auto_refresh(self) -> bool:
        """Attempt to refresh the access token using the stored refresh_token.
        Returns True if successful and session_state is updated."""
        refresh_tok = st.session_state.get("refresh_token")
        if not refresh_tok:
            return False
        url = f"{self._base_url}/api/v1/auth/refresh"
        try:
            resp = requests.post(
                url, json={"refresh_token": refresh_tok}, timeout=_TIMEOUT_SECONDS
            )
            if resp.status_code == 200:
                data = resp.json()
                st.session_state["token"] = data["access_token"]
                if data.get("refresh_token"):
                    st.session_state["refresh_token"] = data["refresh_token"]
                return True
        except Exception:
            pass
        return False

    def _post(self, path: str, *, json: dict | None = None, headers: dict | None = None) -> dict:
        url = f"{self._base_url}{path}"
        try:
            response = requests.post(url, json=json, headers=headers, timeout=_TIMEOUT_SECONDS)
            # Auto-refresh on 401 for authenticated requests
            if response.status_code == 401 and headers and "Authorization" in headers:
                if self._try_auto_refresh():
                    headers = {**headers, "Authorization": f"Bearer {st.session_state['token']}"}
                    response = requests.post(url, json=json, headers=headers, timeout=_TIMEOUT_SECONDS)
            response.raise_for_status()
            return self._ok(response.json())
        except requests.exceptions.Timeout:
            return self._err("Request timed out. Please try again.")
        except requests.exceptions.ConnectionError:
            return self._err("Cannot connect to the server. Is the backend running?")
        except requests.exceptions.HTTPError as exc:
            try:
                detail = exc.response.json().get("detail", str(exc))
                if isinstance(detail, dict):
                    detail = detail.get("detail", str(exc))
            except Exception:
                detail = str(exc)
            return self._err(detail)

    def _get(self, path: str, *, headers: dict | None = None) -> dict:
        url = f"{self._base_url}{path}"
        try:
            response = requests.get(url, headers=headers, timeout=_TIMEOUT_SECONDS)
            # Auto-refresh on 401 for authenticated requests
            if response.status_code == 401 and headers and "Authorization" in headers:
                if self._try_auto_refresh():
                    headers = {**headers, "Authorization": f"Bearer {st.session_state['token']}"}
                    response = requests.get(url, headers=headers, timeout=_TIMEOUT_SECONDS)
            response.raise_for_status()
            return self._ok(response.json())
        except requests.exceptions.Timeout:
            return self._err("Request timed out. Please try again.")
        except requests.exceptions.ConnectionError:
            return self._err("Cannot connect to the server. Is the backend running?")
        except requests.exceptions.HTTPError as exc:
            try:
                detail = exc.response.json().get("detail", str(exc))
                if isinstance(detail, dict):
                    detail = detail.get("detail", str(exc))
            except Exception:
                detail = str(exc)
            return self._err(detail)

    # ------------------------------------------------------------------
    # Auth endpoints
    # ------------------------------------------------------------------

    def signup(self, email: str, password: str, first_name: str, last_name: str) -> dict:
        """POST /api/v1/auth/signup — create account + send OTP."""
        return self._post(
            "/api/v1/auth/signup",
            json={
                "firstName": first_name,
                "lastName": last_name,
                "email": email,
                "password": password,
            },
        )

    def login(self, email: str, password: str, remember_me: bool = False) -> dict:
        """POST /api/v1/auth/login — authenticate + get tokens."""
        return self._post(
            "/api/v1/auth/login",
            json={"email": email, "password": password, "remember_me": remember_me},
        )

    def verify_otp(self, email: str, otp: str, remember_me: bool = False) -> dict:
        """POST /api/v1/auth/verify-otp — verify email + get tokens."""
        return self._post(
            "/api/v1/auth/verify-otp",
            json={"email": email, "otp": otp, "remember_me": remember_me},
        )

    def resend_otp(self, email: str) -> dict:
        """POST /api/v1/auth/resend-otp — send fresh OTP."""
        return self._post("/api/v1/auth/resend-otp", json={"email": email})

    def refresh_token(self, refresh_token: str) -> dict:
        """POST /api/v1/auth/refresh — rotate tokens."""
        return self._post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )

    def logout(self, refresh_token: str | None = None) -> dict:
        """POST /api/v1/auth/logout — revoke refresh token."""
        return self._post(
            "/api/v1/auth/logout",
            json={"refresh_token": refresh_token} if refresh_token else None,
        )

    def verify_token(self, token: str) -> dict:
        """POST /api/v1/auth/verify-token — check access token validity."""
        return self._post(
            "/api/v1/auth/verify-token",
            headers={"Authorization": f"Bearer {token}"},
        )

    def get_me(self, token: str) -> dict:
        """GET /api/v1/auth/me — get current user profile."""
        return self._get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )

    # ── Forgot password flow ──

    def forgot_password(self, email: str) -> dict:
        """POST /api/v1/auth/forgot-password — request reset code."""
        return self._post("/api/v1/auth/forgot-password", json={"email": email})

    def verify_reset_token(self, email: str, otp: str) -> dict:
        """POST /api/v1/auth/verify-reset-token — validate reset code."""
        return self._post(
            "/api/v1/auth/verify-reset-token",
            json={"email": email, "otp": otp},
        )

    def reset_password(self, email: str, token: str, new_password: str) -> dict:
        """POST /api/v1/auth/reset-password — set new password."""
        return self._post(
            "/api/v1/auth/reset-password",
            json={"email": email, "token": token, "new_password": new_password},
        )

    # ------------------------------------------------------------------
    # Generic helpers (used by scan page and other pages)
    # ------------------------------------------------------------------

    def get(self, path: str, *, headers: dict | None = None) -> dict:
        """Generic GET request."""
        return self._get(path, headers=headers)

    def post(
        self,
        path: str,
        *,
        json: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
    ) -> dict:
        """Generic POST — supports custom timeout for long-running calls."""
        if timeout is None:
            return self._post(path, json=json, headers=headers)
        url = f"{self._base_url}{path}"
        try:
            response = requests.post(
                url, json=json, headers=headers, timeout=timeout,
            )
            # Auto-refresh on 401 for authenticated requests
            if response.status_code == 401 and headers and "Authorization" in headers:
                if self._try_auto_refresh():
                    headers = {**headers, "Authorization": f"Bearer {st.session_state['token']}"}
                    response = requests.post(url, json=json, headers=headers, timeout=timeout)
            response.raise_for_status()
            return self._ok(response.json())
        except requests.exceptions.Timeout:
            return self._err("Request timed out. Please try again.")
        except requests.exceptions.ConnectionError:
            return self._err("Cannot connect to the server. Is the backend running?")
        except requests.exceptions.HTTPError as exc:
            try:
                detail = exc.response.json().get("detail", str(exc))
                if isinstance(detail, dict):
                    detail = detail.get("detail", str(exc))
            except Exception:
                detail = str(exc)
            return self._err(detail)
