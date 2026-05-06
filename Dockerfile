# 1. Use a Python base image
FROM python:3.10-slim

# 2. Install the C++ compiler and build tools
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# 3. Set the working directory
WORKDIR /app

# 4. Copy all files from your root to the container
COPY . .

# 5. Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# 6. Compile the C++ Tactical Engine
# We use -pthread to support the asynchronous discovery logic
RUN g++ -std=c++11 -pthread aegis_sentinel.cpp -o aegis_engine && chmod +x aegis_engine

# 7. Expose the port (Render uses 10000 by default, but we'll stick to 5000)
EXPOSE 5000

# 8. Start the application using Gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
