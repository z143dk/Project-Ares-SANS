# Project Ares - SANS "Find Evil!" Hackathon

Welcome to **Project Ares**, our dedicated repository for the upcoming SANS hackathon! 

## Mission Objective
Our goal is to build an autonomous defensive cyber agent (Ares) capable of hunting for threats ("Find Evil") faster than a human operator. We are aiming to close the "7-minute breakout window" by automating digital forensics and incident response (DFIR).

We will be using the **OpenClaw architecture** as a blueprint to build a **Custom MCP (Model Context Protocol) Server**. This will allow our AI agent to securely access and execute tools from the SANS SIFT workstation.

## Collaboration Setup (USA to Italy)
Since we are building this together across time zones, here is how we are staying in sync:

1. **GitHub (Code Sync):** This repository is our single source of truth. Always `git pull` before starting work, and `git push` when you are done.
2. **Discord (Comms & Screen Share):** We will use our Discord server for voice comms, screen sharing, and quick debugging sessions.
3. **Tailscale (Secure Network):** We will use Tailscale to create a secure, private network between our machines. This allows us to securely test the agent without exposing our home networks to the internet.

## Repository Structure
- `src/`: Contains the main Python source code for the Custom MCP Server and the Agent logic.
- `docs/`: (To be created) Will contain our notes, hackathon rules, and architecture diagrams.
- `requirements.txt`: Python dependencies needed to run the project.

## Getting Started
1. Clone this repository to your local machine.
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Check the `src/` folder for the starter MCP server code.

Let's win this! 🛡️
