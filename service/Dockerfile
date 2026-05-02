FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY src/SignMeMaybe.csproj ./
RUN dotnet restore SignMeMaybe.csproj

COPY src/. ./
RUN dotnet publish SignMeMaybe.csproj -c Release -o /app/publish --no-restore


FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime

RUN groupadd --system service \
    && useradd --system --gid service --uid 10001 --create-home service

RUN mkdir /data && chown service:service /data

WORKDIR /app

COPY --from=build /app/publish ./

ENV ASPNETCORE_URLS=http://0.0.0.0:1984
ENV ASPNETCORE_ENVIRONMENT=Production

EXPOSE 1984

USER service

ENTRYPOINT ["dotnet", "SignMeMaybe.dll"]