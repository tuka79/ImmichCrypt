FROM scratch
COPY ImmichCrypt /proxy
EXPOSE 2300
ENTRYPOINT ["/proxy"]
