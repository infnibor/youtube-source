package dev.lavalink.youtube;

public class YoutubeSourceOptions {
    private boolean allowSearch = true;
    private boolean allowDirectVideoIds = true;
    private boolean allowDirectPlaylistIds = true;
    private String cipherEndpoint = "http://localhost:8001/decrypt_signature";
    private String cipherBearerToken = "";

    public boolean isAllowSearch() {
        return allowSearch;
    }

    public boolean isAllowDirectVideoIds() {
        return allowDirectVideoIds;
    }

    public boolean isAllowDirectPlaylistIds() {
        return allowDirectPlaylistIds;
    }

    public String getCipherEndpoint() {
        return cipherEndpoint;
    }

    public String getCipherBearerToken() {
        return cipherBearerToken;
    }

    public YoutubeSourceOptions setAllowSearch(boolean allowSearch) {
        this.allowSearch = allowSearch;
        return this;
    }

    public YoutubeSourceOptions setAllowDirectVideoIds(boolean allowDirectVideoIds) {
        this.allowDirectVideoIds = allowDirectVideoIds;
        return this;
    }

    public YoutubeSourceOptions setAllowDirectPlaylistIds(boolean allowDirectPlaylistIds) {
        this.allowDirectPlaylistIds = allowDirectPlaylistIds;
        return this;
    }

    public YoutubeSourceOptions setCipherEndpoint(String cipherEndpoint) {
        this.cipherEndpoint = cipherEndpoint;
        return this;
    }

    public YoutubeSourceOptions setCipherBearerToken(String cipherBearerToken) {
        this.cipherBearerToken = cipherBearerToken;
        return this;
    }
}
