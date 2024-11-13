import React, { useState, useEffect } from 'react';
import './App.css';
import { registerUser, loginUser, getPolls, voteOnPoll } from './services/api';

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState(localStorage.getItem('access_token'));
  const [polls, setPolls] = useState([]);
  const [message, setMessage] = useState('');

  useEffect(() => {
    if (token) {
      getPolls(token).then((data) => setPolls(data));
    }
  }, [token]);

  const handleRegister = async () => {
    try {
      const data = await registerUser(username, password);
      setMessage(data.message);
    } catch (error) {
      setMessage(error.response.data.message);
    }
  };

  const handleLogin = async () => {
    try {
      const data = await loginUser(username, password);
      setToken(data.access_token);
      localStorage.setItem('access_token', data.access_token);
      setMessage('Logged in successfully!');
    } catch (error) {
      setMessage(error.response.data.message);
    }
  };

  const handleVote = async (pollId) => {
    try {
      const data = await voteOnPoll(pollId, token);
      setMessage(data.message);
    } catch (error) {
      setMessage(error.response.data.message);
    }
  };

  return (
    <div className="App">
      <h1>Online Voting System</h1>

      {!token ? (
        <div>
          <h2>Login or Register</h2>
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
          <button onClick={handleRegister}>Register</button>
          <button onClick={handleLogin}>Login</button>
        </div>
      ) : (
        <div>
          <h2>Polls</h2>
          <ul>
            {polls.map((poll) => (
              <li key={poll.id}>
                {poll.question}
                <button onClick={() => handleVote(poll.id)}>Vote</button>
              </li>
            ))}
          </ul>
        </div>
      )}

      {message && <p>{message}</p>}
    </div>
  );
}

export default App;
