```bash
git clone https://github.com/yakirp/clerk_python_example.git
cd clerk_python_example
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload

