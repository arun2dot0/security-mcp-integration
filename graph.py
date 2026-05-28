from fastapi import FastAPI
from strawberry.fastapi import GraphQLRouter

from schema import schema

app = FastAPI()
graphql_app = GraphQLRouter(schema, path="/graphql")
app.include_router(graphql_app)

@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("graph:app", host="127.0.0.1", port=8000, reload=True)      