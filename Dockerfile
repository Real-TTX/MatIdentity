# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------
# The build runs on the builder's own platform: the published app is portable (no native host), so the arm64 image needs no emulation here.
FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG Channel=local
ARG BuildNumber=0
ARG BuildDate=
WORKDIR /src

# Restore first (better layer caching).
COPY ["global.json", "Directory.Build.props", "./"]
COPY ["src/MatIdentity.Core/MatIdentity.Core.csproj", "src/MatIdentity.Core/"]
COPY ["src/MatIdentity.Web/MatIdentity.Web.csproj", "src/MatIdentity.Web/"]
RUN dotnet restore "src/MatIdentity.Web/MatIdentity.Web.csproj"

COPY src src
# Fall back to today's date when BuildDate is not supplied, so the version never ends in "-".
RUN BUILD_DATE="${BuildDate:-$(date -u +%Y%m%d)}" && \
    dotnet publish "src/MatIdentity.Web/MatIdentity.Web.csproj" \
    -c Release -o /app/publish --no-restore \
    -p:UseAppHost=false \
    -p:Channel=$Channel -p:BuildNumber=$BuildNumber -p:BuildDate=$BUILD_DATE

# ---------------------------------------------------------------------------
# Runtime stage (ASP.NET Core base image)
# ---------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app

ENV HTTP_PORTS=2300 \
    ASPNETCORE_ENVIRONMENT=Production \
    MatIdentity__DataPath=/data \
    DOTNET_gcServer=0 \
    DOTNET_TieredPGO=1

# Database, settings, the keys of the cookies and of the tokens: one volume, owned by the unprivileged user of the image
# (MatIdentity needs no Docker socket and no root).
# The placeholder makes Docker copy the folder (and its owner) into a new, empty volume; without a file in it a named volume stays owned by root.
RUN mkdir -p /data && touch /data/.matidentity && chown -R app:app /data
VOLUME ["/data"]
EXPOSE 2300

COPY --from=build /app/publish .
USER app

# The app checks itself (/api/health), so the image needs no extra tools.
HEALTHCHECK --interval=30s --timeout=8s --start-period=30s --retries=3 \
    CMD ["dotnet", "MatIdentity.Web.dll", "--healthcheck"]

ENTRYPOINT ["dotnet", "MatIdentity.Web.dll"]
