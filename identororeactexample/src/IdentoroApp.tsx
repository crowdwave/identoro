import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Route, Routes, Link, Navigate } from 'react-router-dom';

interface AuthState {
    username: string;
    signedIn: boolean;
    name: string;
}

interface SigninResponse {
    userId: string;
    message: string;
}

interface AuthResponse {
    username: string;
    name: string;
}

interface CommonProps {
    urlPathPrefix?: string;
}

// Wrapper function for fetch with CSRF token handling
const fetchWithCSRF = async (url: string, options: RequestInit = {}) => {
    // Ensure headers exist in options
    options.headers = options.headers || {};

    // Include the CSRF token in headers if it exists
    let csrfToken = (window as any).csrfToken;
    if (!csrfToken) {
        // Request a new CSRF token from /refresh endpoint
        const refreshResponse = await fetch(`${(window as any).urlPathPrefix}/refresh`, {
            method: 'GET',
        });
        if (refreshResponse.ok) {
            csrfToken = refreshResponse.headers.get('CSRF-Token');
            if (csrfToken) {
                (window as any).csrfToken = csrfToken;
            } else {
                alert('Error: No CSRF token received');
            }
        } else {
            alert('Error: Unable to refresh CSRF token');
        }
    }

    if (csrfToken) {
        (options.headers as Record<string, string>)['CSRF-Token'] = csrfToken;
    }

    // Perform the fetch request
    const response = await fetch(url, options);

    // Extract CSRF token from response headers and store it in window if found
    const newCsrfToken = response.headers.get('CSRF-Token');
    if (newCsrfToken) {
        (window as any).csrfToken = newCsrfToken;
    }

    return response;
};

const Signup: React.FC<CommonProps> = ({ urlPathPrefix = '' }) => {
    const [username, setUsername] = useState<string>('');
    const [email, setEmail] = useState<string>('');
    const [password, setPassword] = useState<string>('');
    const [firstname, setFirstname] = useState<string>('');
    const [lastname, setLastname] = useState<string>('');
    const [recaptchaResponse, setRecaptchaResponse] = useState<string>('');
    const [message, setMessage] = useState<string>('');

    const handleSignup = async () => {
        try {
            const response = await fetchWithCSRF(`${urlPathPrefix}/signup`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username,
                    email,
                    password,
                    firstname,
                    lastname,
                    'g-recaptcha-response': recaptchaResponse,
                }),
            });
            const data = await response.json();
            setMessage(data.message);
        } catch (error) {
            const err = error as Error;
            setMessage('Error signing up');
            alert('Error signing up: ' + err.message);
        }
    };

    return (
        <div>
            <h2>Signup</h2>
            <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)} />
            <input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)} />
            <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)} />
            <input
                type="text"
                placeholder="Firstname"
                value={firstname}
                onChange={(e) => setFirstname(e.target.value)} />
            <input
                type="text"
                placeholder="Lastname"
                value={lastname}
                onChange={(e) => setLastname(e.target.value)} />
            <input
                type="text"
                placeholder="reCAPTCHA Response"
                value={recaptchaResponse}
                onChange={(e) => setRecaptchaResponse(e.target.value)}
            />
            <button onClick={handleSignup}>Signup</button>
            {message && <p>{message}</p>}
        </div>
    );
};

const Signin: React.FC<{ setAuthState: React.Dispatch<React.SetStateAction<AuthState>> } & CommonProps> = ({ setAuthState, urlPathPrefix = '' }) => {
    const [username, setUsername] = useState<string>('');
    const [password, setPassword] = useState<string>('');
    const [message, setMessage] = useState<string>('');

    const handleSignin = async () => {
        try {
            const response = await fetchWithCSRF(`${urlPathPrefix}/signin`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username,
                    password,
                }),
            });
            const data: SigninResponse = await response.json();
            setMessage(data.message);
            if (response.status === 200 || response.status === 303) {
                setAuthState({ username, signedIn: true, name: '' });
                localStorage.setItem('userId', data.userId);
            }
        } catch (error) {
            const err = error as Error;
            setMessage('Error signing in');
            alert('Error signing in: ' + err.message);
        }
    };

    return (
        <div>
            <h2>Signin</h2>
            <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)} />
            <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)} />
            <button onClick={handleSignin}>Signin</button>
            {message && <p>{message}</p>}
        </div>
    );
};

const Signout: React.FC<{ setAuthState: React.Dispatch<React.SetStateAction<AuthState>> } & CommonProps> = ({ setAuthState, urlPathPrefix = '' }) => {
    const [message, setMessage] = useState<string>('');

    const handleSignout = async () => {
        try {
            const response = await fetchWithCSRF(`${urlPathPrefix}/signout`, {
                method: 'GET',
            });
            const data = await response.json();
            setMessage(data.message);
            setAuthState({ username: '', signedIn: false, name: '' });
            localStorage.removeItem('userId');
        } catch (error) {
            const err = error as Error;
            setMessage('Error signing out');
            alert('Error signing out: ' + err.message);
        }
    };

    return (
        <div>
            <h2>Signout</h2>
            <button onClick={handleSignout}>Signout</button>
            {message && <p>{message}</p>}
        </div>
    );
};

const ForgotPassword: React.FC<CommonProps> = ({ urlPathPrefix = '' }) => {
    const [email, setEmail] = useState<string>('');
    const [message, setMessage] = useState<string>('');

    const handleForgotPassword = async () => {
        try {
            const response = await fetchWithCSRF(`${urlPathPrefix}/forgot`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email }),
            });
            const data = await response.json();
            setMessage(data.message);
        } catch (error) {
            const err = error as Error;
            setMessage('Error requesting password reset');
            alert('Error requesting password reset: ' + err.message);
        }
    };

    return (
        <div>
            <h2>Forgot Password</h2>
            <input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)} />
            <button onClick={handleForgotPassword}>Request Password Reset</button>
            {message && <p>{message}</p>}
        </div>
    );
};

const ResetPassword: React.FC<CommonProps> = ({ urlPathPrefix = '' }) => {
    const [token, setToken] = useState<string>('');
    const [newPassword, setNewPassword] = useState<string>('');
    const [message, setMessage] = useState<string>('');

    const handleResetPassword = async () => {
        try {
            const response = await fetchWithCSRF(`${urlPathPrefix}/reset`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    token,
                    new_password: newPassword,
                }),
            });
            const data = await response.json();
            setMessage(data.message);
        } catch (error) {
            const err = error as Error;
            setMessage('Error resetting password');
            alert('Error resetting password: ' + err.message);
        }
    };

    return (
        <div>
            <h2>Reset Password</h2>
            <input
                type="text"
                placeholder="Token"
                value={token}
                onChange={(e) => setToken(e.target.value)} />
            <input
                type="password"
                placeholder="New Password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)} />
            <button onClick={handleResetPassword}>Reset Password</button>
            {message && <p>{message}</p>}
        </div>
    );
};

const VerifyAccount: React.FC<CommonProps> = ({ urlPathPrefix = '' }) => {
    const [token, setToken] = useState<string>('');
    const [message, setMessage] = useState<string>('');

    const handleVerifyAccount = async () => {
        try {
            const response = await fetchWithCSRF(`${urlPathPrefix}/verify?token=${token}`, {
                method: 'GET',
            });
            const data = await response.json();
            setMessage(data.message);
        } catch (error) {
            const err = error as Error;
            setMessage('Error verifying account');
            alert('Error verifying account: ' + err.message);
        }
    };

    return (
        <div>
            <h2>Verify Account</h2>
            <input
                type="text"
                placeholder="Token"
                value={token}
                onChange={(e) => setToken(e.target.value)} />
            <button onClick={handleVerifyAccount}>Verify Account</button>
            {message && <p>{message}</p>}
        </div>
    );
};

const Home: React.FC<{ authState: AuthState } & CommonProps> = ({ authState, urlPathPrefix = '' }) => {
    return (
        <div>
            <h1>Welcome to Identoro User Management</h1>
            {authState.signedIn ? (
                <p>
                    You are signed in as {authState.username}. Your name is {authState.name}.
                </p>
            ) : (
                <p>You are not signed in</p>
            )}
            <nav>
                <ul>
                    <li>
                        <Link to={`${urlPathPrefix}/signup`}>Signup</Link>
                    </li>
                    <li>
                        <Link to={`${urlPathPrefix}/signin`}>Signin</Link>
                    </li>
                    <li>
                        <Link to={`${urlPathPrefix}/signout`}>Signout</Link>
                    </li>
                    <li>
                        <Link to={`${urlPathPrefix}/forgot-password`}>Forgot Password</Link>
                    </li>
                    <li>
                        <Link to={`${urlPathPrefix}/reset-password`}>Reset Password</Link>
                    </li>
                    <li>
                        <Link to={`${urlPathPrefix}/verify-account`}>Verify Account</Link>
                    </li>
                </ul>
            </nav>
        </div>
    );
};

export const IdentoroRoutes: React.FC<CommonProps> = ({ urlPathPrefix = '' }) => {
    const [authState, setAuthState] = useState<AuthState>({ username: '', signedIn: false, name: '' });

    useEffect(() => {
        // Check if the user is signed in by making a request to the server
        const checkAuth = async () => {
            const userId = localStorage.getItem('userId');
            if (userId) {
                try {
                    const response = await fetchWithCSRF(`${urlPathPrefix}/me`);
                    const data: AuthResponse = await response.json();
                    if (response.status === 200) {
                        setAuthState({ username: data.username, signedIn: true, name: data.name });
                    }
                } catch (error) {
                    const err = error as Error;
                    setAuthState({ username: '', signedIn: false, name: '' });
                    alert('Error checking authentication: ' + err.message);
                }
            }
        };

        checkAuth();
    }, [urlPathPrefix]);

    // Store urlPathPrefix in window for global access
    useEffect(() => {
        (window as any).urlPathPrefix = urlPathPrefix;
    }, [urlPathPrefix]);

    return (
        <Routes>
            <Route
                path={`${urlPathPrefix}/signup`}
                element={<Signup urlPathPrefix={urlPathPrefix} />} />
            <Route
                path={`${urlPathPrefix}/signin`}
                element={<Signin
                    setAuthState={setAuthState}
                    urlPathPrefix={urlPathPrefix} />} />
            <Route
                path={`${urlPathPrefix}/signout`}
                element={<Signout
                    setAuthState={setAuthState}
                    urlPathPrefix={urlPathPrefix} />} />
            <Route
                path={`${urlPathPrefix}/forgot-password`}
                element={<ForgotPassword urlPathPrefix={urlPathPrefix} />} />
            <Route
                path={`${urlPathPrefix}/reset-password`}
                element={<ResetPassword urlPathPrefix={urlPathPrefix} />} />
            <Route
                path={`${urlPathPrefix}/verify-account`}
                element={<VerifyAccount urlPathPrefix={urlPathPrefix} />} />
            <Route
                path={`${urlPathPrefix}/home`}
                element={<Home
                    authState={authState}
                    urlPathPrefix={urlPathPrefix} />} />
        </Routes>
    );
};
