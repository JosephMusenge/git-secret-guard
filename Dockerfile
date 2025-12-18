# STAGE 1: Build
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

WORKDIR /src

# copy everything first
COPY . .

# restore dependencies
RUN dotnet restore GitSecretGuard.sln

# build the application in Release mode
RUN dotnet build GitSecretGuard.sln -c Release

# run tests
RUN dotnet test GitSecretGuard.sln -c Release --no-build

# publish the CLI
RUN dotnet publish src/GitSecretGuard.Cli/GitSecretGuard.Cli.csproj -c Release -o /app/publish

# STAGE 2: Runtime
FROM mcr.microsoft.com/dotnet/runtime:8.0 AS runtime

LABEL maintainer="Your Name <your.email@example.com>"
LABEL description="Pre-commit secret detection for developers"

# create a non-root user for security
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid appuser --shell /bin/bash --create-home appuser

WORKDIR /app

# copy the published app from the build stage
COPY --from=build /app/publish .

# change ownership to non-root user
RUN chown -R appuser:appuser /app

USER appuser

# set the entry point
ENTRYPOINT ["dotnet", "git-secret-guard.dll"]

CMD ["--help"]