from fastapi import FastAPI
from fastapi.responses import HTMLResponse


app = FastAPI()


@app.get("/greet")
def greet_user(name: str):
    """
    Vulnerable endpoint that renders user input without escaping.
    Allows XSS attacks through the name parameter.
    """
    html_content = f"<html><body><h1>Hello, {name}!</h1></body></html>"

    return HTMLResponse(content=html_content)


@app.get("/search")
def search_results(query: str):
    """
    Another XSS vulnerability in search functionality.
    """
    results_html = f"""
    <html>
        <body>
            <h2>Search results for: {query}</h2>
            <p>Your search term was: {query}</p>
        </body>
    </html>
    """

    return HTMLResponse(content=results_html)
