import axios from 'axios';

// Flask API URL
const API_URL = 'http://localhost:5000/api';  // Change this to your Flask API URL if different

// User Registration
export const registerUser = async (username, password) => {
    const response = await axios.post(`${API_URL}/register`, { username, password });
    return response.data;
};

// User Login
export const loginUser = async (username, password) => {
    const response = await axios.post(`${API_URL}/login`, { username, password });
    return response.data;
};

// Get Active Polls
export const getPolls = async (token) => {
    const response = await axios.get(`${API_URL}/polls`, {
        headers: { Authorization: `Bearer ${token}` },
    });
    return response.data;
};

// Vote on a Poll
export const voteOnPoll = async (pollId, token) => {
    const response = await axios.post(`${API_URL}/vote/${pollId}`, {}, {
        headers: { Authorization: `Bearer ${token}` },
    });
    return response.data;
};
