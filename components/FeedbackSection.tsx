import React, { useState, useEffect } from 'react';
import { supabase, Review } from '../services/supabaseClient';
import { Star, Send, User, MessageSquare, Loader2, AlertCircle, Quote } from 'lucide-react';

interface Props {
  translate?: (key: string) => string;
}

export const FeedbackSection: React.FC<Props> = ({ translate }) => {
  const [reviews, setReviews] = useState<Review[]>([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [connectionError, setConnectionError] = useState(false);
  const t = translate || ((k: string) => k);
  
  // Form State
  const [name, setName] = useState('');
  const [title, setTitle] = useState(''); // Added Title state
  const [rating, setRating] = useState(5);
  const [comment, setComment] = useState('');
  const [error, setError] = useState('');

  // Identifier for this application in the shared reviews table
  const SITE_NAME = 'container-security-guide';

  useEffect(() => {
    fetchReviews();
  }, []);

  const fetchReviews = async () => {
    try {
      const { data, error } = await supabase
        .from('reviews')
        .select('*')
        .eq('site_name', SITE_NAME) // Only fetch reviews for this app
        .order('created_at', { ascending: false })
        .limit(10);

      if (error) {
        throw error;
      }
      
      if (data) {
        setReviews(data);
        setConnectionError(false);
      }
    } catch (err: any) {
      console.warn("Supabase Error:", err.message);
      setConnectionError(true);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    // Validate all mandatory fields per schema
    if (!name.trim() || !comment.trim() || !title.trim()) {
      setError(t('Please fill in all fields.'));
      return;
    }
    setError('');
    setSubmitting(true);

    try {
      const { error } = await supabase
        .from('reviews')
        .insert([{ 
          site_name: SITE_NAME, // Mandatory
          name, 
          title, // Mandatory
          rating, 
          comment 
        }]);

      if (error) throw error;

      // Reset form and refetch
      setName('');
      setTitle('');
      setComment('');
      setRating(5);
      await fetchReviews();
    } catch (err: any) {
      setError(t('Failed to submit review.') + ' ' + (err.message || 'Check network'));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="mt-12 pt-8 border-t border-gray-200 dark:border-gray-800">
      <h3 className="text-2xl font-bold text-gray-900 dark:text-white mb-6 flex items-center gap-2">
        <MessageSquare className="w-6 h-6 text-sec-red" />
        {t('Community Feedback')}
      </h3>

      <div className="grid md:grid-cols-2 gap-8">
        {/* Form */}
        <div className="bg-white dark:bg-card-bg p-6 rounded-xl border border-gray-300 dark:border-gray-700 shadow-sm">
          <h4 className="text-lg font-semibold mb-4 dark:text-gray-200">{t('Leave a Review')}</h4>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-bold uppercase text-gray-500 mb-1">{t('Name')}</label>
              <input 
                type="text" 
                value={name}
                onChange={e => setName(e.target.value)}
                className="w-full bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded p-2 text-sm dark:text-white focus:ring-2 focus:ring-sec-red focus:outline-none"
                placeholder="Cyber_Punk_2077"
              />
            </div>

            <div>
              <label className="block text-xs font-bold uppercase text-gray-500 mb-1">Title</label>
              <input 
                type="text" 
                value={title}
                onChange={e => setTitle(e.target.value)}
                className="w-full bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded p-2 text-sm dark:text-white focus:ring-2 focus:ring-sec-red focus:outline-none"
                placeholder="Great resource for K8s!"
              />
            </div>

            <div>
              <label className="block text-xs font-bold uppercase text-gray-500 mb-1">{t('Rating')}</label>
              <div className="flex gap-2">
                {[1, 2, 3, 4, 5].map((star) => (
                  <button
                    key={star}
                    type="button"
                    onClick={() => setRating(star)}
                    className="focus:outline-none transition-transform hover:scale-110"
                  >
                    <Star className={`w-6 h-6 ${star <= rating ? 'fill-yellow-500 text-yellow-500' : 'text-gray-300 dark:text-gray-600'}`} />
                  </button>
                ))}
              </div>
            </div>
            <div>
              <label className="block text-xs font-bold uppercase text-gray-500 mb-1">{t('Comment')}</label>
              <textarea 
                value={comment}
                onChange={e => setComment(e.target.value)}
                rows={3}
                className="w-full bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded p-2 text-sm dark:text-white focus:ring-2 focus:ring-sec-red focus:outline-none resize-none"
                placeholder="Great insights on Shift Left..."
              />
            </div>
            
            {error && <p className="text-xs text-red-500">{error}</p>}

            <button 
              type="submit" 
              disabled={submitting}
              className="w-full bg-sec-red hover:bg-red-700 text-white font-bold py-2 px-4 rounded-lg flex items-center justify-center gap-2 transition disabled:opacity-50"
            >
              {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
              {t('Submit Review')}
            </button>
          </form>
        </div>

        {/* List */}
        <div className="space-y-4 max-h-[600px] overflow-y-auto pr-2">
          {loading ? (
             <div className="flex justify-center p-8"><Loader2 className="w-8 h-8 animate-spin text-gray-400" /></div>
          ) : connectionError ? (
             <div className="flex flex-col items-center justify-center p-8 text-center bg-red-50 dark:bg-red-900/10 rounded-lg border border-red-100 dark:border-red-900/30">
                <AlertCircle className="w-8 h-8 text-red-500 mb-2" />
                <p className="text-sm text-red-600 dark:text-red-400">{t('Unable to load reviews.')}</p>
                <p className="text-xs text-gray-500 mt-1">{t("Check if 'reviews' table exists in Supabase.")}</p>
             </div>
          ) : reviews.length === 0 ? (
             <div className="text-center p-8 text-gray-500 italic">{t('No reviews yet. Be the first!')}</div>
          ) : (
            reviews.map((rev, idx) => (
              <div key={rev.id || idx} className="bg-gray-50 dark:bg-gray-800/50 p-4 rounded-lg border border-gray-200 dark:border-gray-700/50 animate-fade-in hover:border-gray-300 dark:hover:border-gray-600 transition-colors">
                 <div className="flex justify-between items-start mb-2">
                    <div className="flex items-center gap-2">
                        <div className="bg-gray-200 dark:bg-gray-700 p-1.5 rounded-full">
                            <User className="w-4 h-4 text-gray-600 dark:text-gray-300" />
                        </div>
                        <div>
                          <span className="font-bold text-sm text-gray-800 dark:text-gray-200 block leading-tight">{rev.name}</span>
                          {rev.title && <span className="text-[10px] font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wide">{rev.title}</span>}
                        </div>
                    </div>
                    <div className="flex">
                        {[...Array(5)].map((_, i) => (
                            <Star key={i} className={`w-3 h-3 ${i < rev.rating ? 'fill-yellow-500 text-yellow-500' : 'text-gray-300 dark:text-gray-600'}`} />
                        ))}
                    </div>
                 </div>
                 
                 <div className="relative pl-3 border-l-2 border-gray-200 dark:border-gray-700 mt-3">
                    <p className="text-sm text-gray-600 dark:text-gray-300 leading-relaxed italic">
                      "{rev.comment}"
                    </p>
                 </div>

                 <div className="flex justify-between items-center mt-3 pt-2 border-t border-gray-100 dark:border-gray-800">
                    <span className="text-[10px] text-gray-400">
                        {rev.created_at ? new Date(rev.created_at).toLocaleDateString() : 'Just now'}
                    </span>
                    {rev.site_name && rev.site_name !== SITE_NAME && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-gray-100 dark:bg-gray-900 text-gray-500 border border-gray-200 dark:border-gray-800">
                        via {rev.site_name}
                      </span>
                    )}
                 </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};