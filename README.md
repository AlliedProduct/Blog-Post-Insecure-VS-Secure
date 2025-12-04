# Blog-Post-Insecure-VS-Secure
This repository contains a simple blog application with two iversions:

- **insecure** – an intentionally vulnerable version  
- **secure** – a hardened version with security controls  

Both versions use **Node.js**, **Express**, and **SQLite3**.  

---

## Requirements

- Node.js
- npm
- SQLite3
- A terminal or VS Code

---

## Running the Application

### 1. Install dependencies
Run this in the root of the repository:

npm install

### 2. Switch to the version you want to run
- Insecure version
git checkout insecure
npm run start:insecure

App will be available @ http://localhost:3000

- Secure version
git checkout secure
npm run start:secure

App will be available @ http://localhost:3001