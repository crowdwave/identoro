import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Route, Routes, Link, Navigate } from 'react-router-dom'; // Updated imports

interface AuthState {
  username: string;
  signedIn: boolean;
  name: string; // Added missing 'name' field
}

interface SigninResponse {
  userId: string;
  message: string;
}

interface AuthResponse {
  username: string;
  name: string;
}

const Signup: React.FC = () => {
  const [username, setUsername] = useState<string>('');
  const [email, setEmail] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [firstname, setFirstname] = useState<string>('');
  const [lastname, setLastname] = useState<string>('');
  const [recaptchaResponse, setRecaptchaResponse] = useState<string>('');
  const [message, setMessage] = useState<string>('');

  const handleSignup = async () => {
    try {
      const response = await fetch('/signup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          username,
          email,
          password,
          firstname,
          lastname,
          'g-recaptcha-response': recaptchaResponse
        })
      });
      const data = await response.json();
      setMessage(data.message);
    } catch (error) {
      setMessage('Error signing up');
    }
  };

  return (
    <div>
      <h2>Signup</h2>
      <input
        type="text"
        placeholder="Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
      />
      <input
        type="email"
        placeholder="Email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
      />
      <input
        type="password"
        placeholder="Password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <input
        type="text"
        placeholder="Firstname"
        value={firstname}
        onChange={(e) => setFirstname(e.target.value)}
      />
      <input
        type="text"
        placeholder="Lastname"
        value={lastname}
        onChange={(e) => setLastname(e.target.value)}
      />
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

const Signin: React.FC<{ setAuthState: React.Dispatch<React.SetStateAction<AuthState>> }> = ({ setAuthState }) => {
  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [message, setMessage] = useState<string>('');

  const handleSignin = async () => {
    try {
      const response = await fetch('/signin', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          username,
          password
        })
      });
      const data: SigninResponse = await response.json();
      setMessage(data.message);
      if (response.status === 200 || response.status === 303) {
        setAuthState({ username, signedIn: true, name: '' }); // Assume name is empty initially
        localStorage.setItem('userId', data.userId);
      }
    } catch (error) {
      setMessage('Error signing in');
    }
  };

  return (
    <div>
      <h2>Signin</h2>
      <input
        type="text"
        placeholder="Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
      />
      <input
        type="password"
        placeholder="Password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <button onClick={handleSignin}>Signin</button>
      {message && <p>{message}</p>}
    </div>
  );
};

const Signout: React.FC<{ setAuthState: React.Dispatch<React.SetStateAction<AuthState>> }> = ({ setAuthState }) => {
  const [message, setMessage] = useState<string>('');

  const handleSignout = async () => {
    try {
      const response = await fetch('/signout', {
        method: 'GET'
      });
      const data = await response.json();
      setMessage(data.message);
      setAuthState({ username: '', signedIn: false, name: '' });
      localStorage.removeItem('userId');
    } catch (error) {
      setMessage('Error signing out');
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

const ForgotPassword: React.FC = () => {
  const [email, setEmail] = useState<string>('');
  const [message, setMessage] = useState<string>('');

  const handleForgotPassword = async () => {
    try {
      const response = await fetch('/forgot', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email })
      });
      const data = await response.json();
      setMessage(data.message);
    } catch (error) {
      setMessage('Error requesting password reset');
    }
  };

  return (
    <div>
      <h2>Forgot Password</h2>
      <input
        type="email"
        placeholder="Email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
      />
      <button onClick={handleForgotPassword}>Request Password Reset</button>
      {message && <p>{message}</p>}
    </div>
  );
};

const ResetPassword: React.FC = () => {
  const [token, setToken] = useState<string>('');
  const [newPassword, setNewPassword] = useState<string>('');
  const [message, setMessage] = useState<string>('');

  const handleResetPassword = async () => {
    try {
      const response = await fetch('/reset', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          token,
          new_password: newPassword
        })
      });
      const data = await response.json();
      setMessage(data.message);
    } catch (error) {
      setMessage('Error resetting password');
    }
  };

  return (
    <div>
      <h2>Reset Password</h2>
      <input
        type="text"
        placeholder="Token"
        value={token}
        onChange={(e) => setToken(e.target.value)}
      />
      <input
        type="password"
        placeholder="New Password"
        value={newPassword}
        onChange={(e) => setNewPassword(e.target.value)}
      />
      <button onClick={handleResetPassword}>Reset Password</button>
      {message && <p>{message}</p>}
    </div>
  );
};

const VerifyAccount: React.FC = () => {
  const [token, setToken] = useState<string>('');
  const [message, setMessage] = useState<string>('');

  const handleVerifyAccount = async () => {
    try {
      const response = await fetch(`/verify?token=${token}`, {
        method: 'GET'
      });
      const data = await response.json();
      setMessage(data.message);
    } catch (error) {
      setMessage('Error verifying account');
    }
  };

  return (
    <div>
      <h2>Verify Account</h2>
      <input
        type="text"
        placeholder="Token"
        value={token}
        onChange={(e) => setToken(e.target.value)}
      />
      <button onClick={handleVerifyAccount}>Verify Account</button>
      {message && <p>{message}</p>}
    </div>
  );
};

const Home: React.FC<{ authState: AuthState }> = ({ authState }) => {
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
            <Link to="/signup">Signup</Link>
          </li>
          <li>
            <Link to="/signin">Signin</Link>
          </li>
          <li>
            <Link to="/signout">Signout</Link>
          </li>
          <li>
            <Link to="/forgot-password">Forgot Password</Link>
          </li>
          <li>
            <Link to="/reset-password">Reset Password</Link>
          </li>
          <li>
            <Link to="/verify-account">Verify Account</Link>
          </li>
        </ul>
      </nav>
    </div>
  );
};

export const IdentoroRoutes: React.FC = () => {
  const [authState, setAuthState] = useState<AuthState>({ username: '', signedIn: false, name: '' });

  useEffect(() => {
    // Check if the user is signed in by making a request to the server
    const checkAuth = async () => {
      const userId = localStorage.getItem('userId');
      if (userId) {
        try {
          const response = await fetch('/me');
          const data: AuthResponse = await response.json();
          if (response.status === 200) {
            setAuthState({ username: data.username, signedIn: true, name: data.name });
          }
        } catch (error) {
          setAuthState({ username: '', signedIn: false, name: '' });
        }
      }
    };

    checkAuth();
  }, []);

  return (
    <Routes>
        <Route path="/signup" element={<Signup />} />
        <Route path="/signin" element={<Signin setAuthState={setAuthState} />} />
        <Route path="/signout" element={<Signout setAuthState={setAuthState} />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/reset-password" element={<ResetPassword />} />
        <Route path="/verify-account" element={<VerifyAccount />} />
        <Route path="/" element={<Home authState={authState} />} />
    </Routes>
  );
};

