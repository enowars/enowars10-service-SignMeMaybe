FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY src/SignMeMaybe.csproj ./
RUN dotnet restore SignMeMaybe.csproj

COPY src/. ./
RUN dotnet publish SignMeMaybe.csproj -c Release -o /app/publish --no-restore


FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime

RUN groupadd --system --gid 10001 service
RUN useradd --system --uid 10001 --gid service service

RUN mkdir /data && chown service:service /data

WORKDIR /app

COPY --from=build /app/publish ./

ENV ASPNETCORE_URLS=http://0.0.0.0:1984
ENV ASPNETCORE_ENVIRONMENT=Production

EXPOSE 1984

ENTRYPOINT ["dotnet", "SignMeMaybe.dll"]