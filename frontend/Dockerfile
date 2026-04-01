FROM node:20-alpine
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
WORKDIR /frontend
COPY package*.json ./
RUN npm install
COPY . .
CMD ["npm", "run", "dev"]
=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY . .
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173"]
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
