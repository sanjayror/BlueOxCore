FROM microsoft/aspnetcore:2.0 AS base
WORKDIR /app
EXPOSE 80

FROM microsoft/aspnetcore-build:2.0 AS build
RUN apt-get update && apt-get -y install sudo
RUN apt-get install -y libgdiplus   
RUN cd /usr/lib
RUN sudo ln -s libgdiplus.so gdiplus.dll
RUN apt-get install -y libgdiplus && cd /usr/lib ln -s libgdiplus.so gdiplus.dll
RUN sudo apt-get update
RUN sudo apt-get install libgdiplus
WORKDIR /src
COPY /BlueOxCore.csproj BlueOxCore/
RUN dotnet restore BlueOxCore/BlueOxCore.csproj
WORKDIR /src/BlueOxCore
COPY . ./.
RUN dotnet build BlueOxCore.csproj -c Release -o /app

FROM build AS publish
RUN dotnet publish BlueOxCore.csproj -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "BlueOxCore.dll"]
