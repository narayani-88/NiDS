# 🚀 NIDS Deployment Guide

## ⚠️ Important Note About Netlify

**NIDS cannot be deployed to Netlify** because:
- Netlify only hosts static websites (HTML, CSS, JavaScript)
- NIDS is a Flask Python application requiring server-side processing
- Network scanning requires system-level access and Python runtime
- AI analysis needs server-side API calls to Google Gemini

## 🌐 Recommended Deployment Options

### 1. 🚀 **Railway** (Recommended - Easy & Free)
```bash
# 1. Install Railway CLI
npm install -g @railway/cli

# 2. Login to Railway
railway login

# 3. Deploy NIDS
railway deploy

# 4. Set environment variables
railway variables set GEMINI_API_KEY=your_api_key_here
```

**Advantages:**
- ✅ Free tier available
- ✅ Automatic HTTPS
- ✅ Easy deployment
- ✅ Environment variable management
- ✅ Custom domains

### 2. 🟣 **Heroku** (Popular Choice)
```bash
# 1. Install Heroku CLI
# Download from: https://devcenter.heroku.com/articles/heroku-cli

# 2. Login and create app
heroku login
heroku create your-nids-app

# 3. Set environment variables
heroku config:set GEMINI_API_KEY=your_api_key_here

# 4. Deploy
git add .
git commit -m "Deploy NIDS"
git push heroku main
```

**Files needed:** ✅ Already created
- `Procfile` ✅
- `runtime.txt` ✅
- `requirements.txt` ✅

### 3. 🔵 **DigitalOcean App Platform**
```bash
# 1. Create account at digitalocean.com
# 2. Go to App Platform
# 3. Connect GitHub repository
# 4. Configure:
#    - Runtime: Python
#    - Build Command: pip install -r requirements.txt
#    - Run Command: python app.py
# 5. Set environment variables in dashboard
```

### 4. 🟠 **AWS Elastic Beanstalk**
```bash
# 1. Install EB CLI
pip install awsebcli

# 2. Initialize and deploy
eb init
eb create nids-production
eb deploy

# 3. Set environment variables
eb setenv GEMINI_API_KEY=your_api_key_here
```

### 5. 🏠 **Local Network Deployment** (For Team Access)
```bash
# 1. Find your local IP
ipconfig  # Windows
ifconfig  # Linux/Mac

# 2. Run NIDS
python app.py

# 3. Access from team devices
# http://your-ip-address:5000
# Example: http://192.168.1.100:5000
```

## 🔧 Pre-Deployment Checklist

### ✅ Security Configuration
```python
# In app.py - Update for production
app.secret_key = 'your-secure-random-key-here'  # Change this!
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')  # Use env vars
```

### ✅ Environment Variables
Set these in your deployment platform:
```bash
GEMINI_API_KEY=your_google_gemini_api_key
FLASK_ENV=production
SECRET_KEY=your_secure_secret_key
```

### ✅ Files Ready for Deployment
- ✅ `Procfile` - Heroku/Railway process definition
- ✅ `runtime.txt` - Python version specification
- ✅ `requirements.txt` - Python dependencies
- ✅ `.gitignore` - Excludes sensitive files
- ✅ Updated `app.py` - Port configuration for cloud

## 🎯 Quick Deploy to Railway (Easiest)

1. **Create Railway Account**: Go to [railway.app](https://railway.app)
2. **Connect GitHub**: Link your GitHub account
3. **Import Repository**: Select your NIDS repository
4. **Set Environment Variables**:
   ```
   GEMINI_API_KEY=your_api_key_here
   ```
5. **Deploy**: Railway automatically detects Flask and deploys
6. **Get URL**: Railway provides a public URL like `https://nids-production.up.railway.app`

## 🔒 Production Security Notes

### 🛡️ Essential Security Updates
```python
# Update app.py for production
import os
from werkzeug.middleware.proxy_fix import ProxyFix

# Security headers
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'change-this-in-production'),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

# Proxy fix for cloud deployment
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
```

### 🔐 API Key Security
- ✅ Never commit API keys to Git
- ✅ Use environment variables
- ✅ Rotate keys regularly
- ✅ Monitor API usage

## 🌍 Sharing with Your Friend

Once deployed, share:
1. **Public URL**: `https://your-nids-app.railway.app`
2. **Login Instructions**: No authentication by default (add if needed)
3. **Usage Guide**: Point them to the AI Analysis and Monitoring features
4. **Network Requirements**: They need to be on the same network for local scanning

## 🚨 Important Limitations for Cloud Deployment

### ⚠️ Network Scanning Limitations
- **Cloud servers can only scan their own network environment**
- **Cannot scan your friend's local network from cloud deployment**
- **For local network scanning, deploy locally or use VPN**

### 💡 Solutions for Remote Network Scanning
1. **Local Deployment**: Run NIDS on local network
2. **VPN Access**: Connect cloud NIDS to local network via VPN
3. **Agent-Based**: Deploy NIDS agents on each network (advanced)

## 🎯 Recommended Approach for Your Use Case

Since you want your friend to use it for their job:

### Option A: Local Deployment (Recommended)
```bash
# Your friend runs NIDS locally on their network
git clone https://github.com/yourusername/nids.git
cd nids
pip install -r requirements.txt
python app.py
# Access: http://localhost:5000
```

### Option B: Cloud + Local Hybrid
```bash
# Deploy to cloud for demo/training
# Use local deployment for actual network scanning
```

## 🆘 Deployment Support

If you encounter issues:
1. Check deployment platform logs
2. Verify environment variables are set
3. Ensure all dependencies are in requirements.txt
4. Test locally first: `python app.py`

---

**🎯 Ready to deploy? Start with Railway for the easiest experience!**
