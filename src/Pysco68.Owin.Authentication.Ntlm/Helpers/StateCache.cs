namespace Pysco68.Owin.Authentication.Ntlm.Security
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
#if NETFULL
    using System.Runtime.Caching;
#elif NETCORE
    using Microsoft.Extensions.Caching.Memory;
#endif

    /// <summary>
    /// An in-memory cache for the login handshakes
    /// </summary>
    class StateCache
    {
        #region fields
        private MemoryCache Cache;

        /// <summary>
        /// Expiration time of a login attempt state in minutes,
        /// defaults to 2
        /// </summary>
        public int ExpirationTime { get; set; }
        #endregion

        /// <summary>
        /// Create a state cache
        /// </summary>
        /// <param name="name"></param>
        public StateCache(string name)
        {
#if NETFULL
            this.Cache = new MemoryCache(name);
#elif NETCORE
            this.Cache = new MemoryCache(new MemoryCacheOptions());
#endif
            this.ExpirationTime = 2;            
        }

        /// <summary>
        /// Try to get a state by its key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        public bool TryGet(string key, out HandshakeState state)
        {
#if NETFULL
            if (Cache.Contains(key))
            {
                object tmp = Cache[key];
                if (tmp != null)
                {
                    state = (HandshakeState)tmp;
                    return true;
                }
            }

            state = default(HandshakeState);
            return false;
#elif NETCORE
            return Cache.TryGetValue(key, out state);
#endif
        }

        /// <summary>
        /// Add a new state to the cache
        /// </summary>
        /// <param name="key"></param>
        /// <param name="state"></param>
        public void Add(string key, HandshakeState state)
        {
#if NETFULL
            this.Cache.Set(key, state, GetCacheItemPolicy(this.ExpirationTime));
#elif NETCORE
            this.Cache.Set(key, state, GetMemoryCacheEntryOptions(this.ExpirationTime));
#endif
        }

#if NETFULL
        /// <summary>
        /// Add a new state to the cache and set a custom cache item policy
        /// </summary>
        /// <param name="key"></param>
        /// <param name="state"></param>
        /// <param name="policy"></param>
        public void Add(string key, HandshakeState state, CacheItemPolicy policy)
        {
            this.Cache.Set(key, state, policy);
        }
#elif NETCORE
        /// <summary>
        /// Add a new state to the cache and set a custom cache item policy
        /// </summary>
        /// <param name="key"></param>
        /// <param name="state"></param>
        /// <param name="policy"></param>
        public void Add(string key, HandshakeState state, MemoryCacheEntryOptions policy)
        {
            this.Cache.Set(key, state, policy);
        }
#endif

        /// <summary>
        /// Remove a key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool TryRemove(string key)
        {
#if NETFULL
            return this.Cache.Remove(key) != null;
#elif NETCORE
            this.Cache.Remove(key);
            return true;
#endif
        }

        #region Helpers
#if NETFULL
        /// <summary>
        /// Gets a cache item policy.
        /// </summary>
        /// <param name="minutes">Absolute expiration time in x minutes</param>
        /// <returns></returns>
        private static CacheItemPolicy GetCacheItemPolicy(int minutes)
        {
            var policy = new CacheItemPolicy()
            {
                Priority = CacheItemPriority.Default,
                AbsoluteExpiration = DateTimeOffset.Now.AddMinutes(minutes),
                RemovedCallback = (item) => 
                {  
                    // dispose cached item at removal
                    var asDisposable = item.CacheItem as IDisposable;
                    if (asDisposable != null)
                        asDisposable.Dispose();
                }
            };
            return policy;
        }
#elif NETCORE
        /// <summary>
        /// Gets a memory cache entry options.
        /// </summary>
        /// <param name="minutes">Absolute expiration time in x minutes</param>
        /// <returns></returns>
        private MemoryCacheEntryOptions GetMemoryCacheEntryOptions(int minutes)
        {
            var options = new MemoryCacheEntryOptions()
            {
                Priority = CacheItemPriority.Normal,
                AbsoluteExpiration = DateTimeOffset.Now.AddMinutes(minutes),
                PostEvictionCallbacks =
                {
                    new PostEvictionCallbackRegistration()
                    {
                        EvictionCallback = (key, item, reason, state) =>
                        {
                            // dispose cached item at removal
                            var asDisposable = item as IDisposable;
                            if (asDisposable != null)
                                asDisposable.Dispose();
                        }
                    }
                }
            };
            return options;
        }
#endif
        #endregion

    }
}
