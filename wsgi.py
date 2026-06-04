from src.app import create_app, initialize_system


application = create_app()

if not initialize_system():
    raise RuntimeError("Agentic IDS failed to initialize. Check model artifacts and runtime configuration.")
