FROM microsoft/aspnetcore:2.0 AS base
WORKDIR /app
EXPOSE 80

FROM microsoft/aspnetcore-build:2.0 AS build
WORKDIR /src
COPY BlueOxCore/BlueOxCore.csproj BlueOxCore/
RUN dotnet restore BlueOxCore/BlueOxCore.csproj
COPY . .
WORKDIR /src/BlueOxCore
RUN dotnet build BlueOxCore.csproj -c Release -o /app

FROM build AS publish
RUN dotnet publish BlueOxCore.csproj -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "BlueOxCore.dll"]
